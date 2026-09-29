"""Jev client (Tier-1 typed-decision scorer) for the SOC alert triage copilot
(docs/architecture.md §5, Phase B task 2, §12).

Transport strategy
-------------------
Before writing a line of this module, `typesafe-sdk` was checked against the REAL PyPI index
(`pip index versions typesafe-sdk` and `pip install typesafe-sdk`, 2026-09-29) rather than assumed
to exist. It DOES exist and installs cleanly: version 0.7.2, pulling in `pydantic>=2.12`,
`tenacity`, and its own HTTP layer, `httpx2` (an httpx-API-compatible transport package, distinct
from the third-party `httpx`; it exposes the same `Client`/`MockTransport`/etc. surface). Its
source was read end-to-end (client, config, transport, errors, retry, question/answer schemas)
before depending on it, specifically to rule out it being an unrelated or malicious package that
happened to share this name:
  - `typesafe_sdk.constants.DEFAULT_BASE_URL == "https://api.typesafe.ai"`,
    `API_KEY_ENV == "TYPESAFE_API_KEY"`, `BASE_URL_ENV == "TYPESAFE_BASE_URL"`,
    `DEFAULT_MODEL == "jev-latest"` -- an exact match for docs/architecture.md §5 and this repo's
    `.env.example` (including the commented-out `TYPESAFE_BASE_URL` override for the OpenRouter
    System One fallback -- setting that env var is enough to redirect the SDK there; no separate
    HTTP client is needed for the fallback path).
  - Its `Choice`/`Noul`/`Score` question types and `ChoiceAnswer`/`NoulAnswer`/`ScoreAnswer`
    response types match §5's question-type table exactly (Choice = named options, Noul = a single
    0-1 probability, Score = an ordered rubric), each score/choice answer carrying a full
    `probabilities` distribution, not just a top confidence value.
  - No `eval`/`exec`/`subprocess`/`os.system`/telemetry beacons/unexpected hosts anywhere in its
    source; `POST {base_url}/v1/systemone` is the only endpoint this module's calls reach.

Given all of that, this module wraps the real SDK rather than hand-rolling an httpx client against
the documented endpoint (the fallback plan if the package had not existed or had not matched the
spec). Callers of THIS module never import or see `typesafe_sdk` directly -- only `JevClient`,
`JevDecision`, and `JevUnavailableError` cross the boundary -- so swapping transports later stays a
one-file change.

The SDK's own built-in retrying is disabled here (`RetryPolicy(max_retries=0)`) in favor of this
module's own bounded-retry loop, so retry/backoff timing is fully under this module's control and
unit-testable without any real sleeping (every `sleep` call is injectable; see tests/).

*** FAIL-SAFE CONTRACT (docs/architecture.md §5, §8) ***
`score_alert` raises `JevUnavailableError` after retries are exhausted, or immediately on any
unrecoverable error (bad request, auth failure, malformed response, etc.). Callers (the policy
engine / ingestion pipeline wiring) MUST catch this and route the alert to `queued` -- NEVER
auto-close an alert on a Jev failure. This is a hard contract other agents' integration work
depends on.

Untrusted input note (docs/architecture.md §10): `untrusted_evidence.raw_log_excerpt` is
attacker-influenced text. This module's job is transport/parsing only -- that string is passed
through to Jev untouched and never used to alter this client's own control flow (no eval, no
dynamic dispatch on response/request content).
"""

from __future__ import annotations

import json
import math
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from dotenv import load_dotenv
from typesafe_sdk import (
    RetryPolicy,
    TypeSafeAPIConnectionError,
    TypeSafeAPIError,
    TypeSafeClient,
    TypeSafeError,
    TypeSafeInternalServerError,
    TypeSafeRateLimitError,
)
from typesafe_sdk import ChoiceAnswer as SdkChoiceAnswer
from typesafe_sdk import NoulAnswer as SdkNoulAnswer
from typesafe_sdk import ScoreAnswer as SdkScoreAnswer
from typesafe_sdk import SystemOneResponse

from question_catalog import (
    BUSINESS_IMPACT_LEVELS,
    QUESTION_CATALOG,
    SEVERITY_LEVELS,
    ChoiceAnswer,
    JevRawAnswers,
    JevStateObject,
    ProbabilityAnswer,
    ScoreAnswer,
)
from rate_limiter import JevRateLimiter

load_dotenv()

# Score-question keys mapped to their ordered rubric levels (question_catalog.py's criteria
# lists), used to translate the SDK's index-keyed score probabilities back into the canonical
# short labels the `jev_decisions` table columns expect (e.g. "high", not the description text
# used as that level's rubric criterion).
_SCORE_LEVELS: dict[str, tuple[str, ...]] = {
    "severity": SEVERITY_LEVELS,
    "business_impact_if_true": BUSINESS_IMPACT_LEVELS,
}

Sleep = Callable[[float], None]
Clock = Callable[[], float]

# Transport routing (docs/architecture.md §5: "If the waitlist hasn't cleared yet,
# point the same SDK at OpenRouter's System One route as a fallback"). This is
# genuinely the current state -- api.typesafe.ai's real 401 was confirmed live
# (see eval/prompt_injection_suite's and eval/benchmark.py's reports). JEV_ROUTE
# defaults to "direct" in CODE so switching back once the waitlist clears is a
# one-line .env change (remove/flip JEV_ROUTE), never a code change. Set
# JEV_ROUTE=openrouter (as this repo's .env currently does) to route through
# OpenRouter's System One endpoint instead, using OPENROUTER_API_KEY (a separate
# credential -- OpenRouter, not TypeSafe) and TYPESAFE_BASE_URL.
#
# IMPORTANT, found by a live test: the "direct" branch below explicitly pins
# api.typesafe.ai rather than leaving base_url=None and trusting the SDK's own
# TYPESAFE_BASE_URL env fallback. A real live call caught why this matters: this
# repo's .env sets TYPESAFE_BASE_URL to the OpenRouter URL (needed for the
# openrouter branch) -- since typesafe_sdk reads that env var itself, independent
# of this wrapper, leaving base_url=None here would ALSO silently redirect the
# "direct" path to OpenRouter's host while still sending the real TYPESAFE_API_KEY
# (a TypeSafe credential, not an OpenRouter one) -- observed live as a 404, wrong
# host/key pairing, not the honest 401 auth failure this path is meant to surface.
_ROUTE_ENV = "JEV_ROUTE"
_DIRECT_BASE_URL = "https://api.typesafe.ai"
_DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1/system-one"


def _resolve_transport(explicit_api_key: str | None, explicit_base_url: str | None) -> tuple[str | None, str | None]:
    """Only steps in when the caller passed neither `api_key` nor `base_url`
    explicitly -- an explicit value (including in tests, which always pass
    `api_key="test-key"`) always wins untouched, exactly as before this routing
    logic existed."""
    if explicit_api_key is not None or explicit_base_url is not None:
        return explicit_api_key, explicit_base_url
    route = os.environ.get(_ROUTE_ENV, "direct").strip().lower()
    if route == "openrouter":
        return (
            os.environ.get("OPENROUTER_API_KEY"),
            os.environ.get("TYPESAFE_BASE_URL") or _DEFAULT_OPENROUTER_BASE_URL,
        )
    # "direct": api_key stays None (the SDK's own TYPESAFE_API_KEY env resolution
    # applies), but base_url is explicitly pinned -- see the comment above.
    return None, _DIRECT_BASE_URL


class JevUnavailableError(Exception):
    """Jev is unavailable: retries were exhausted, or an unrecoverable error occurred.

    *** CALLERS MUST CATCH THIS *** (docs/architecture.md §5, §8): route the alert to `queued`.
    NEVER auto-close an alert because Jev failed -- a failure here carries no information about
    the alert's actual severity, and auto-closing on it would silently drop true positives.
    """


@dataclass(frozen=True)
class JevDecision:
    """Maps cleanly onto the `jev_decisions` table columns (infra/migrations/001_init.sql).

    `confidence_margin` and the extra `confidence_entropy`/`per_question_*` fields are computed by
    THIS client from the full probability arrays -- never taken from a single bundled confidence
    field (docs/architecture.md §5: "don't rely on the single confidence field alone when two
    options are close").
    """

    # --- jev_decisions columns ---
    triage_verdict: str
    is_false_positive_prob: float
    severity: str
    attack_category: str
    needs_more_context_prob: float
    business_impact_if_true: str
    confidence_margin: float
    raw_response: dict[str, Any]
    latency_ms: int
    # --- extra, not DB columns, but derived from the same probability arrays ---
    confidence_entropy: float = field(compare=False)
    per_question_margins: dict[str, float] = field(compare=False)
    per_question_entropies: dict[str, float] = field(compare=False)
    raw_answers: JevRawAnswers = field(compare=False)


def compute_margin_and_entropy(probabilities: dict[str, float]) -> tuple[float, float]:
    """Compute `margin = top1_prob - top2_prob` and Shannon `entropy` (nats) from a FULL
    probability distribution -- never trust a single bundled confidence field (docs/architecture.md
    §5). Zero/near-zero probabilities are skipped in the entropy sum (0 * log(0) is conventionally
    0, and log(0) is undefined)."""
    if not probabilities:
        return 0.0, 0.0
    ordered = sorted(probabilities.values(), reverse=True)
    top1 = ordered[0]
    top2 = ordered[1] if len(ordered) > 1 else 0.0
    margin = top1 - top2
    entropy = -sum(p * math.log(p) for p in probabilities.values() if p > 0)
    return margin, entropy


def _estimate_tokens(payload: dict[str, Any]) -> int:
    """Rough pre-call token estimate for the rate limiter's token bucket (~4 chars/token, the
    same heuristic commonly used for English text/JSON). Jev's curated state object is small
    (docs/architecture.md §5: "Large, noisy state lowers accuracy -- send the curated object
    above"), so this only matters for correctness of the bucket math, not for actually binding in
    practice."""
    encoded = json.dumps(payload, ensure_ascii=False, default=str)
    return max(1, len(encoded) // 4)


def _convert_choice_answer(sdk_answer: SdkChoiceAnswer) -> ChoiceAnswer:
    return ChoiceAnswer(selected=sdk_answer.choice, probabilities=dict(sdk_answer.probabilities))


def _convert_probability_answer(sdk_answer: SdkNoulAnswer) -> ProbabilityAnswer:
    return ProbabilityAnswer(probability=sdk_answer.noul)


def _convert_score_answer(question_key: str, sdk_answer: SdkScoreAnswer) -> ScoreAnswer:
    levels = _SCORE_LEVELS[question_key]
    probabilities = {levels[index]: prob for index, prob in sdk_answer.probabilities.items() if 0 <= index < len(levels)}
    for level in levels:
        probabilities.setdefault(level, 0.0)
    if sdk_answer.probabilities:
        top_index = max(sdk_answer.probabilities, key=lambda index: sdk_answer.probabilities[index])
        selected = levels[top_index] if 0 <= top_index < len(levels) else levels[0]
    else:
        selected = levels[0]
    return ScoreAnswer(selected=selected, expected_value=sdk_answer.score, probabilities=probabilities)


class JevClient:
    """Sync client wrapping `typesafe_sdk.TypeSafeClient`. See this module's docstring for the
    transport rationale and the fail-safe contract `score_alert` callers must honor.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        rate_limiter: JevRateLimiter | None = None,
        max_retries: int = 3,
        backoff_initial: float = 0.5,
        backoff_max: float = 8.0,
        sleep: Sleep = time.sleep,
        clock: Clock = time.monotonic,
        timeout: float = 10.0,
        transport: Any | None = None,
    ) -> None:
        """`transport` is passed straight through to `typesafe_sdk.TypeSafeClient` (an
        `httpx2.BaseTransport`) -- tests use `httpx2.MockTransport` here to avoid any real network
        calls (see tests/test_client.py).

        SDK client construction is deliberately LAZY (see `_ensure_sdk_client`), not done here.
        A live test caught a real bug this fixes: `TypeSafeClient(...)` can itself raise
        (e.g. `TypeSafeError("No API key was provided...")` when JEV_ROUTE=openrouter is
        configured but OPENROUTER_API_KEY is still blank -- a real, observed state while that
        credential is pending). Raising straight out of `__init__` bypassed this class's own
        fail-safe translation entirely (the caller's `except JevUnavailableError` only wraps
        `score_alert()`, not `JevClient()` construction), which meant the whole live pipeline
        silently skipped policy evaluation, notification, AND Tier-2 brief generation for that
        alert -- a strictly worse outcome than the documented "fail safe to queued" contract.
        Deferring construction into `score_alert()`'s own try/except means ANY Jev
        setup/config/transport problem now correctly becomes a `JevUnavailableError`, exactly
        like an HTTP-level failure does.
        """
        self._api_key, self._base_url = _resolve_transport(api_key, base_url)
        self._model = model
        self._timeout = timeout
        self._transport = transport
        self._sdk_client: TypeSafeClient | None = None
        self._rate_limiter = rate_limiter or JevRateLimiter(clock=clock)
        self._max_retries = max_retries
        self._backoff_initial = backoff_initial
        self._backoff_max = backoff_max
        self._sleep = sleep
        self._perf_counter: Callable[[], float] = time.perf_counter

    def _ensure_sdk_client(self) -> TypeSafeClient:
        """Construct the underlying SDK client on first use, translating any construction-time
        failure (bad/missing API key, invalid base_url, etc.) into `JevUnavailableError` -- see
        the long comment in `__init__` for why this must not happen eagerly there."""
        if self._sdk_client is None:
            try:
                self._sdk_client = TypeSafeClient(
                    api_key=self._api_key,
                    base_url=self._base_url,
                    model=self._model,
                    retry=RetryPolicy(max_retries=0),  # this module's own retry loop is authoritative
                    timeout=self._timeout,
                    transport=self._transport,
                )
            except (TypeSafeError, TypeSafeAPIError) as exc:
                raise JevUnavailableError(f"Jev client could not be configured: {exc}") from exc
        return self._sdk_client

    def score_alert(self, state_object: dict[str, Any] | JevStateObject) -> JevDecision:
        """Score one alert against all six questions in `question_catalog.QUESTION_CATALOG`, in a
        single call (docs/architecture.md §5: "All six answered in one call per alert").

        Raises:
            JevUnavailableError: retries exhausted, or an unrecoverable error occurred. See this
                module's docstring for the fail-safe contract callers MUST honor.
        """
        state = state_object if isinstance(state_object, JevStateObject) else JevStateObject.model_validate(state_object)
        payload = state.model_dump(mode="json")
        estimated_tokens = _estimate_tokens(payload)

        # Raises JevUnavailableError directly on a construction-time problem (bad/missing key,
        # etc.) -- deliberately NOT inside the retry loop below, since a broken client
        # configuration will never succeed on retry (that's not what the retry loop is for).
        sdk_client = self._ensure_sdk_client()

        last_error: BaseException | None = None
        attempt = 0
        while attempt <= self._max_retries:
            self._rate_limiter.acquire(estimated_tokens, sleep=self._sleep)
            started = self._perf_counter()
            try:
                response = sdk_client.system_one(state=payload, questions=QUESTION_CATALOG)
            except (TypeSafeRateLimitError, TypeSafeInternalServerError, TypeSafeAPIConnectionError) as exc:
                # Retryable per docs/architecture.md §5: 429 and 5xx (TypeSafeAPIConnectionError
                # covers connection failures/timeouts, also transient).
                last_error = exc
                attempt += 1
                if attempt > self._max_retries:
                    break
                self._sleep(self._compute_backoff(attempt, exc))
                continue
            except TypeSafeAPIError as exc:
                # Any other 4xx (400/401/403/404/422): not retried, per spec.
                raise JevUnavailableError(f"Jev returned a non-retryable error: {exc}") from exc
            except TypeSafeError as exc:
                # SDK-level validation errors (bad request shape, malformed response, etc.): also
                # unrecoverable without changing the call itself, so don't burn retries on them.
                raise JevUnavailableError(f"Jev call failed (unrecoverable): {exc}") from exc
            else:
                latency_ms = int(round((self._perf_counter() - started) * 1000))
                return self._to_decision(response, latency_ms)

        raise JevUnavailableError(f"Jev call failed after {self._max_retries} retries: {last_error}") from last_error

    def _compute_backoff(self, attempt: int, exc: BaseException) -> float:
        if isinstance(exc, TypeSafeRateLimitError) and exc.retry_after_ms is not None:
            return max(0.0, exc.retry_after_ms / 1000)
        delay = self._backoff_initial * (2 ** (attempt - 1))
        return min(self._backoff_max, delay)

    def _to_decision(self, response: SystemOneResponse, latency_ms: int) -> JevDecision:
        choices = response.choices
        scores = response.scores
        nouls = response.nouls

        try:
            triage_verdict = _convert_choice_answer(choices["triage_verdict"])
            is_false_positive = _convert_probability_answer(nouls["is_false_positive"])
            severity = _convert_score_answer("severity", scores["severity"])
            attack_category = _convert_choice_answer(choices["attack_category"])
            needs_more_context = _convert_probability_answer(nouls["needs_more_context"])
            business_impact_if_true = _convert_score_answer("business_impact_if_true", scores["business_impact_if_true"])
        except KeyError as exc:
            # A question from QUESTION_CATALOG is missing from the response entirely -- treat as
            # unrecoverable (never fabricate a decision from an incomplete answer set).
            raise JevUnavailableError(f"Jev response is missing an expected answer: {exc}") from exc

        raw_answers = JevRawAnswers(
            triage_verdict=triage_verdict,
            is_false_positive=is_false_positive,
            severity=severity,
            attack_category=attack_category,
            needs_more_context=needs_more_context,
            business_impact_if_true=business_impact_if_true,
        )

        per_question_margins: dict[str, float] = {}
        per_question_entropies: dict[str, float] = {}
        for key, answer in (
            ("triage_verdict", triage_verdict),
            ("severity", severity),
            ("attack_category", attack_category),
            ("business_impact_if_true", business_impact_if_true),
        ):
            margin, entropy = compute_margin_and_entropy(answer.probabilities)
            per_question_margins[key] = margin
            per_question_entropies[key] = entropy

        # The overall summary field the policy engine keys off of: triage_verdict's distribution
        # (docs/architecture.md §5: "e.g. from triage_verdict's distribution, since that's the
        # field the policy engine keys off of").
        confidence_margin = per_question_margins["triage_verdict"]
        confidence_entropy = per_question_entropies["triage_verdict"]

        return JevDecision(
            triage_verdict=triage_verdict.selected,
            is_false_positive_prob=is_false_positive.probability,
            severity=severity.selected,
            attack_category=attack_category.selected,
            needs_more_context_prob=needs_more_context.probability,
            business_impact_if_true=business_impact_if_true.selected,
            confidence_margin=confidence_margin,
            raw_response=response.model_dump(mode="json"),
            latency_ms=latency_ms,
            confidence_entropy=confidence_entropy,
            per_question_margins=per_question_margins,
            per_question_entropies=per_question_entropies,
            raw_answers=raw_answers,
        )

    def close(self) -> None:
        # No-op if the SDK client was never constructed (e.g. score_alert() was never called,
        # or _ensure_sdk_client() itself failed and raised JevUnavailableError) -- nothing to
        # close in that case.
        if self._sdk_client is not None:
            self._sdk_client.close()

    def __enter__(self) -> "JevClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
