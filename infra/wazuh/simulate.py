"""simulate.py -- Wazuh live-demo scenario simulator (Phase C task 4, docs/architecture.md §12).

Running a full real Wazuh manager/indexer/dashboard stack is heavy and not required
for the MVP's live-demo requirement ("a simulated Wazuh SSH brute-force alert is
ingested..."). This script is the supported/tested path: it loads a realistic,
Wazuh-shaped alert fixture from scenarios/<name>.json and POSTs it directly to
ingest-api's POST /webhook/wazuh endpoint (services/ingest-api/main.py), which
accepts any non-empty JSON object as the raw Wazuh payload.

Usage:
    python simulate.py --scenario ssh_brute_force --url http://localhost:8000
    python simulate.py --scenario all
    python simulate.py --scenario sudo_abuse --repeat 5

See README.md in this directory for the full walkthrough (including the optional
full-Wazuh-stack path).
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import requests

SCENARIOS_DIR = Path(__file__).parent / "scenarios"

ALL_SCENARIOS = ["ssh_brute_force", "sudo_abuse", "new_listening_service"]

# Matches the fixtures' timestamp format, e.g. "2026-09-20T03:12:44.118+0000"
# (milliseconds, no colon in the UTC offset).
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"


def load_scenario(name: str) -> dict[str, Any]:
    """Load scenarios/<name>.json. Raises FileNotFoundError with a clear message
    if the scenario doesn't exist."""
    path = SCENARIOS_DIR / f"{name}.json"
    if not path.is_file():
        available = ", ".join(ALL_SCENARIOS)
        raise FileNotFoundError(
            f"no such scenario '{name}' (looked for {path}); available: {available}"
        )
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _format_timestamp(dt: datetime) -> str:
    """Inverse of _TIMESTAMP_FORMAT parsing, truncated to milliseconds to match
    the fixtures' style (e.g. '...44.118+0000', not 6-digit microseconds)."""
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    millis = f"{dt.microsecond // 1000:03d}"
    offset = dt.strftime("%z") or "+0000"
    return f"{base}.{millis}{offset}"


def jitter_payload(payload: dict[str, Any], rep_index: int) -> dict[str, Any]:
    """Return a copy of `payload` with `id` and `timestamp` mutated so a repeat
    replay doesn't collide with the original fixture (or with other repeats) on
    ingest-api's (source, external_id) unique index -- see main.py's
    webhook_wazuh handler, which uses the Wazuh alert `id` as external_id.

    `full_log` and every other field are left untouched: only the two fields
    that drive idempotency/dedup and the alert's apparent time are mutated.
    """
    mutated = copy.deepcopy(payload)

    original_id = str(mutated.get("id", uuid.uuid4().hex))
    mutated["id"] = f"{original_id}-r{rep_index}-{uuid.uuid4().hex[:8]}"

    original_ts = mutated.get("timestamp")
    if isinstance(original_ts, str):
        try:
            parsed = datetime.strptime(original_ts, _TIMESTAMP_FORMAT)
        except ValueError:
            parsed = datetime.now(timezone.utc)
        # Small forward jitter per repeat (0-5 minutes, spread by index) so a
        # batch of repeats looks like a realistic burst rather than identical
        # timestamps -- useful for exercising similar_alerts_24h-style features.
        jittered = parsed + timedelta(seconds=rep_index * 37)
        mutated["timestamp"] = _format_timestamp(jittered)

    return mutated


def post_alert(
    session: requests.Session, url: str, payload: dict[str, Any], timeout: float = 10.0
) -> requests.Response:
    endpoint = url.rstrip("/") + "/webhook/wazuh"
    return session.post(endpoint, json=payload, timeout=timeout)


def run_scenario(
    session: requests.Session, url: str, name: str, repeat: int, timeout: float
) -> bool:
    """POST one scenario `repeat` times. Returns True iff every attempt got a
    2xx response."""
    try:
        base_payload = load_scenario(name)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"[{name}] FAILED to load: {exc}")
        return False

    all_ok = True
    for rep_index in range(repeat):
        if repeat > 1:
            payload = jitter_payload(base_payload, rep_index)
        else:
            payload = base_payload

        try:
            response = post_alert(session, url, payload, timeout=timeout)
        except requests.exceptions.RequestException as exc:
            print(f"[{name}] rep {rep_index + 1}/{repeat}: request failed: {exc}")
            all_ok = False
            continue

        ok = 200 <= response.status_code < 300
        all_ok = all_ok and ok
        try:
            body = response.json()
        except ValueError:
            body = response.text
        print(
            f"[{name}] rep {rep_index + 1}/{repeat}: "
            f"status={response.status_code} body={body}"
        )

    return all_ok


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "POST simulated Wazuh alert scenarios directly to ingest-api's "
            "POST /webhook/wazuh endpoint (the supported live-demo path -- see README.md)."
        )
    )
    parser.add_argument(
        "--scenario",
        required=True,
        choices=[*ALL_SCENARIOS, "all"],
        help="Which scenario to fire, or 'all' to fire all three in sequence.",
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8000",
        help="ingest-api base URL (default: %(default)s). POSTs go to {url}/webhook/wazuh.",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help=(
            "Replay the scenario N times (default: %(default)s). N > 1 jitters "
            "the id/timestamp per repeat so redelivery-idempotency doesn't "
            "collapse them into one row -- useful for generating volume to "
            "exercise similar_alerts_24h-style features later."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout per request, in seconds (default: %(default)s).",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.repeat < 1:
        parser.error("--repeat must be >= 1")

    scenarios = ALL_SCENARIOS if args.scenario == "all" else [args.scenario]

    session = requests.Session()
    webhook_secret = os.environ.get("WAZUH_WEBHOOK_SECRET")
    if webhook_secret:
        # Matches services/ingest-api/main.py's _check_webhook_secret. Only needed
        # once WAZUH_WEBHOOK_SECRET is actually set server-side; unset (the .env
        # default) means the endpoint accepts unauthenticated requests, so this is
        # a no-op then.
        session.headers["X-Webhook-Secret"] = webhook_secret
    all_ok = True
    for name in scenarios:
        ok = run_scenario(session, args.url, name, args.repeat, args.timeout)
        all_ok = all_ok and ok

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
