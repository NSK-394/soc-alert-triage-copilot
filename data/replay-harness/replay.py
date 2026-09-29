"""replay.py — Replay Harness (Phase A task 5, docs/architecture.md §7).

Reads a converted, labeled dataset file (JSON Lines — one /replay request body
per line, see README.md for the exact contract) and POSTs each line into
ingest-api's `POST {url}/replay` endpoint at a configurable rate.

Usage:
    python replay.py --input path/to/file.jsonl --url http://localhost:8000 --rate 20 --limit 2000

The pure logic (rate-limiter sleep-time computation, line parsing/validation,
and retry eligibility) is factored into standalone functions so it can be
unit-tested without any real HTTP calls or wall-clock sleeping — see
tests/test_replay.py.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

import requests

logger = logging.getLogger("replay")

# --------------------------------------------------------------------------
# Rate limiter (pure)
# --------------------------------------------------------------------------


def compute_sleep_seconds(rate: float, sent_count: int, elapsed: float) -> float:
    """Return how long to sleep before sending the (sent_count+1)-th record.

    Pure function: given a target `rate` (records/sec), how many records have
    already been sent (`sent_count`, 0-indexed — i.e. the count sent *before*
    this one), and how much wall-clock time has elapsed since the run started
    (`elapsed`, seconds), compute the sleep needed so the long-run average
    stays at `rate`.

    The ideal elapsed time to have sent `sent_count` records at `rate`/sec is
    `sent_count / rate`. If we're already past that point (a slow HTTP call
    ate the budget), sleep is 0 — we never try to "catch up" by bursting
    negative sleep. `rate <= 0` disables throttling entirely (send as fast as
    possible).
    """
    if rate <= 0:
        return 0.0
    ideal_elapsed = sent_count / rate
    return max(0.0, ideal_elapsed - elapsed)


# --------------------------------------------------------------------------
# Line parsing / validation (pure)
# --------------------------------------------------------------------------


def parse_jsonl_line(line: str, line_num: int) -> tuple[Optional[dict], Optional[str]]:
    """Parse and minimally validate one line of the .jsonl input.

    Returns (record, error):
      - blank/whitespace-only line -> (None, None)  — silently skipped, not an error
      - malformed JSON             -> (None, "<warning message with line_num>")
      - valid JSON but not a dict  -> (None, "<warning message with line_num>")
      - dict missing 'source' or 'raw' -> (None, "<warning message with line_num>")
      - otherwise                  -> (record_dict, None)
    """
    stripped = line.strip()
    if not stripped:
        return None, None

    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError as exc:
        return None, f"line {line_num}: malformed JSON, skipping ({exc})"

    if not isinstance(obj, dict):
        return None, f"line {line_num}: not a JSON object (got {type(obj).__name__}), skipping"

    missing = [key for key in ("source", "raw") if key not in obj]
    if missing:
        return None, f"line {line_num}: missing required key(s) {missing}, skipping"

    return obj, None


# --------------------------------------------------------------------------
# Retry eligibility (pure)
# --------------------------------------------------------------------------

_RETRYABLE_EXCEPTION_TYPES = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
)


def is_retryable_status(status_code: int) -> bool:
    """5xx is treated as transient (server-side) and retried. 4xx is a bad
    record (client error) and is never retried."""
    return 500 <= status_code < 600


def is_retryable_exception(exc: BaseException) -> bool:
    """Connection errors and timeouts are transient; anything else (bad URL,
    too many redirects, etc.) is a configuration problem and is not retried."""
    return isinstance(exc, _RETRYABLE_EXCEPTION_TYPES)


# --------------------------------------------------------------------------
# HTTP send with bounded retry
# --------------------------------------------------------------------------


@dataclass
class SendResult:
    ok: bool
    status_code: Optional[int]
    error: Optional[str]
    attempts: int


def send_record(
    session: "requests.Session",
    url: str,
    record: dict,
    timeout: float,
    max_attempts: int = 3,
    backoff_base: float = 0.5,
    sleep_func: Callable[[float], None] = time.sleep,
) -> SendResult:
    """POST `record` as JSON to `url`, retrying transient failures.

    Retries (bounded, short exponential backoff: backoff_base * 2**(attempt-1))
    on connection errors, timeouts, and 5xx responses. Does not retry on 4xx
    (a bad record, not a transient failure) or on non-transient exceptions.
    200 and 201 are treated as success.
    """
    last_status: Optional[int] = None
    last_error: Optional[str] = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = session.post(url, json=record, timeout=timeout)
        except requests.exceptions.RequestException as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if is_retryable_exception(exc) and attempt < max_attempts:
                sleep_func(backoff_base * (2 ** (attempt - 1)))
                continue
            return SendResult(ok=False, status_code=None, error=last_error, attempts=attempt)

        if response.status_code in (200, 201):
            return SendResult(ok=True, status_code=response.status_code, error=None, attempts=attempt)

        last_status = response.status_code
        last_error = f"HTTP {response.status_code}: {getattr(response, 'text', '')[:200]}"
        if is_retryable_status(response.status_code) and attempt < max_attempts:
            sleep_func(backoff_base * (2 ** (attempt - 1)))
            continue
        return SendResult(ok=False, status_code=last_status, error=last_error, attempts=attempt)

    # Unreachable in practice (loop always returns), but keeps mypy/pylint happy.
    return SendResult(ok=False, status_code=last_status, error=last_error, attempts=max_attempts)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Replay a labeled .jsonl dataset into ingest-api's /replay endpoint "
            "at a configurable rate."
        )
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to a .jsonl file, one /replay request body per line (see README.md).",
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8000",
        help="ingest-api base URL (default: %(default)s). POSTs go to {url}/replay.",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=10.0,
        help="Target alerts per second (default: %(default)s). Use 0 to disable throttling.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Stop after N valid records have been attempted (default: no limit).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP timeout per request, in seconds (default: %(default)s).",
    )
    return parser


def print_summary(
    lines_read: int,
    attempted: int,
    sent_ok: int,
    failures: list[tuple[int, Optional[int], Optional[str]]],
    elapsed: float,
) -> None:
    failed = len(failures)
    effective_rate = attempted / elapsed if elapsed > 0 else 0.0

    print()
    print("=" * 64)
    print("Replay summary")
    print("=" * 64)
    print(f"  Lines read (incl. skipped/blank): {lines_read}")
    print(f"  Records attempted (sent to API):  {attempted}")
    print(f"  Sent OK:                          {sent_ok}")
    print(f"  Failed:                           {failed}")
    print(f"  Elapsed:                          {elapsed:.2f}s")
    print(f"  Effective rate:                   {effective_rate:.2f} records/sec")
    if failures:
        print()
        print("  First failures:")
        for line_num, status, error in failures[:5]:
            print(f"    line {line_num}: status={status} error={error}")
    print("=" * 64)


def run(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    endpoint = args.url.rstrip("/") + "/replay"
    session = requests.Session()

    lines_read = 0
    attempted = 0
    sent_ok = 0
    failures: list[tuple[int, Optional[int], Optional[str]]] = []

    start = time.monotonic()
    try:
        with open(args.input, "r", encoding="utf-8") as handle:
            for line_num, line in enumerate(handle, start=1):
                if args.limit is not None and attempted >= args.limit:
                    break

                lines_read += 1
                record, error = parse_jsonl_line(line, line_num)
                if error:
                    logger.warning(error)
                    continue
                if record is None:
                    continue  # blank line, silently skipped

                elapsed = time.monotonic() - start
                sleep_for = compute_sleep_seconds(args.rate, attempted, elapsed)
                if sleep_for > 0:
                    time.sleep(sleep_for)

                attempted += 1
                result = send_record(session, endpoint, record, args.timeout)
                if result.ok:
                    sent_ok += 1
                else:
                    failures.append((line_num, result.status_code, result.error))
                    logger.warning(
                        "line %d: send failed after %d attempt(s): %s",
                        line_num,
                        result.attempts,
                        result.error,
                    )
    except FileNotFoundError:
        logger.error("input file not found: %s", args.input)
        return 2

    elapsed_total = time.monotonic() - start
    print_summary(lines_read, attempted, sent_ok, failures, elapsed_total)

    return 0 if not failures else 1


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
