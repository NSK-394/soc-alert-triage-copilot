"""JevClient integration tests -- HTTP is mocked with `httpx2.MockTransport` (httpx2 is the
transport `typesafe-sdk` itself uses; its API mirrors `httpx`'s `MockTransport` exactly). No real
network calls happen anywhere in this suite."""

from __future__ import annotations

import httpx2
import pytest
from pydantic import ValidationError

from client import JevClient, JevUnavailableError

SAMPLE_STATE = {
    "alert": {
        "source": "wazuh",
        "rule_id": "5712",
        "rule_description": "SSHD brute force trying to get access",
        "rule_level": 10,
        "mitre_hint": ["T1110"],
        "timestamp_utc": "2026-09-20T03:12:44Z",
    },
    "entities": {"src_ip": "203.0.113.7", "user": "svc-backup", "host": "db-prod-02"},
    "derived": {
        "failed_auth_10m": 212,
        "successful_auth_after_failures": True,
        "off_hours": True,
        "src_ip_first_seen_days": 0,
        "src_ip_reputation": "malicious",
        "host_criticality": "crown_jewel",
        "rule_historical_fp_rate": 0.62,
        "similar_alerts_24h": 3,
    },
    "untrusted_evidence": {
        "raw_log_excerpt": "Accepted password for svc-backup from 203.0.113.7 port 51022"
    },
}


def _system_one_body(
    *,
    triage_probs: dict[str, float] | None = None,
    severity_probs: dict[str, float] | None = None,
    business_impact_probs: dict[str, float] | None = None,
    attack_category_probs: dict[str, float] | None = None,
    is_false_positive: float = 0.12,
    needs_more_context: float = 0.65,
) -> dict:
    triage_probs = triage_probs or {
        "true_positive": 0.70,
        "benign_positive": 0.10,
        "false_positive": 0.15,
        "other": 0.05,
    }
    severity_probs = severity_probs or {"0": 0.05, "1": 0.10, "2": 0.60, "3": 0.25}  # -> "high"
    business_impact_probs = business_impact_probs or {"0": 0.2, "1": 0.5, "2": 0.3}  # -> "medium"
    attack_category_probs = attack_category_probs or {
        "credential_access": 0.80,
        "discovery": 0.15,
        "other": 0.05,
    }

    def expected_value(probs: dict[str, float]) -> float:
        return sum(int(level) * p for level, p in probs.items())

    return {
        "model": "jev-latest",
        "usage": {"input_tokens": 150, "output_tokens": 40},
        "answers": {
            "triage_verdict": {
                "type": "choice",
                "choice": max(triage_probs, key=lambda k: triage_probs[k]),
                "confidence": max(triage_probs.values()),
                "probabilities": triage_probs,
            },
            "is_false_positive": {"type": "noul", "noul": is_false_positive},
            "severity": {
                "type": "score",
                "score": expected_value(severity_probs),
                "confidence": max(severity_probs.values()),
                "legend": {"0": "informational", "1": "low", "2": "high", "3": "critical"},
                "probabilities": severity_probs,
            },
            "attack_category": {
                "type": "choice",
                "choice": max(attack_category_probs, key=lambda k: attack_category_probs[k]),
                "confidence": max(attack_category_probs.values()),
                "probabilities": attack_category_probs,
            },
            "needs_more_context": {"type": "noul", "noul": needs_more_context},
            "business_impact_if_true": {
                "type": "score",
                "score": expected_value(business_impact_probs),
                "confidence": max(business_impact_probs.values()),
                "legend": {"0": "low", "1": "medium", "2": "high"},
                "probabilities": business_impact_probs,
            },
        },
    }


def _fail_sleep(seconds: float) -> None:
    raise AssertionError(f"sleep() should not have been called (requested {seconds}s)")


def test_score_alert_happy_path() -> None:
    body = _system_one_body()

    def handler(request: httpx2.Request) -> httpx2.Response:
        assert request.url.path == "/v1/systemone"
        assert request.headers["authorization"] == "Bearer test-key"
        return httpx2.Response(200, json=body)

    client = JevClient(
        api_key="test-key",
        transport=httpx2.MockTransport(handler),
        sleep=_fail_sleep,
    )
    decision = client.score_alert(SAMPLE_STATE)

    assert decision.triage_verdict == "true_positive"
    assert decision.is_false_positive_prob == pytest.approx(0.12)
    assert decision.severity == "high"  # index 2 of SEVERITY_LEVELS
    assert decision.attack_category == "credential_access"
    assert decision.needs_more_context_prob == pytest.approx(0.65)
    assert decision.business_impact_if_true == "medium"  # index 1 of BUSINESS_IMPACT_LEVELS
    assert decision.confidence_margin == pytest.approx(0.70 - 0.15)
    assert decision.latency_ms >= 0
    assert decision.raw_response["model"] == "jev-latest"
    assert decision.raw_answers.triage_verdict.selected == "true_positive"
    assert set(decision.per_question_margins) == {
        "triage_verdict",
        "severity",
        "attack_category",
        "business_impact_if_true",
    }


def test_construction_time_config_error_becomes_jev_unavailable_not_raw_sdk_error() -> None:
    """Regression test for a real bug caught live: constructing JevClient() with no
    resolvable API key anywhere (env cleared by the autouse fixture) used to raise a raw
    typesafe_sdk.TypeSafeError straight out of JevClient() -- BEFORE score_alert() was ever
    called, bypassing this class's whole fail-safe contract entirely. A real deployment hit
    this exact case: JEV_ROUTE=openrouter configured but OPENROUTER_API_KEY still blank. The
    fix defers SDK client construction into score_alert()'s own try/except (see client.py's
    _ensure_sdk_client) so ANY Jev setup problem -- not just an HTTP-level failure -- becomes
    JevUnavailableError, matching docs/architecture.md §5/§8's fail-safe contract."""
    client = JevClient()  # no api_key, no transport -- construction itself must NOT raise
    with pytest.raises(JevUnavailableError):
        client.score_alert(SAMPLE_STATE)
    client.close()  # must not raise even though the SDK client was never successfully built


def test_rejects_state_object_before_any_http_call() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:  # pragma: no cover
        raise AssertionError("must not make an HTTP call for an invalid state object")

    client = JevClient(api_key="test-key", transport=httpx2.MockTransport(handler), sleep=_fail_sleep)
    malformed_state = {"alert": {}, "entities": {}, "derived": {}, "untrusted_evidence": {}}
    with pytest.raises(ValidationError):
        client.score_alert(malformed_state)


def test_429_then_success_retries_and_returns_decision() -> None:
    call_count = 0
    body = _system_one_body()

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx2.Response(429, json={"error": "rate limited"})
        return httpx2.Response(200, json=body)

    sleeps: list[float] = []
    client = JevClient(
        api_key="test-key",
        transport=httpx2.MockTransport(handler),
        sleep=sleeps.append,
        backoff_initial=0.01,
        backoff_max=0.02,
    )
    decision = client.score_alert(SAMPLE_STATE)

    assert call_count == 2
    assert len(sleeps) == 1  # exactly one retry backoff, no real time elapsed
    assert decision.triage_verdict == "true_positive"


def test_5xx_then_success_retries() -> None:
    call_count = 0
    body = _system_one_body()

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            return httpx2.Response(503, json={"error": "temporarily unavailable"})
        return httpx2.Response(200, json=body)

    sleeps: list[float] = []
    client = JevClient(
        api_key="test-key",
        transport=httpx2.MockTransport(handler),
        sleep=sleeps.append,
        max_retries=3,
        backoff_initial=0.01,
        backoff_max=0.02,
    )
    decision = client.score_alert(SAMPLE_STATE)

    assert call_count == 3
    assert len(sleeps) == 2
    assert decision.severity == "high"


def test_exhausted_retries_raises_jev_unavailable_error() -> None:
    call_count = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal call_count
        call_count += 1
        return httpx2.Response(500, json={"error": "always down"})

    client = JevClient(
        api_key="test-key",
        transport=httpx2.MockTransport(handler),
        sleep=lambda seconds: None,
        max_retries=2,
        backoff_initial=0.001,
        backoff_max=0.001,
    )
    with pytest.raises(JevUnavailableError):
        client.score_alert(SAMPLE_STATE)

    # max_retries=2 -> 1 initial attempt + 2 retries = 3 total calls.
    assert call_count == 3


def test_non_retryable_4xx_fails_fast_without_retrying() -> None:
    call_count = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal call_count
        call_count += 1
        return httpx2.Response(401, json={"error": "invalid api key"})

    client = JevClient(
        api_key="test-key",
        transport=httpx2.MockTransport(handler),
        sleep=_fail_sleep,
        max_retries=3,
    )
    with pytest.raises(JevUnavailableError):
        client.score_alert(SAMPLE_STATE)

    assert call_count == 1  # not retried


def test_malformed_response_is_unrecoverable_not_retried() -> None:
    call_count = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal call_count
        call_count += 1
        return httpx2.Response(200, json={"not": "a valid system-one response"})

    client = JevClient(
        api_key="test-key",
        transport=httpx2.MockTransport(handler),
        sleep=_fail_sleep,
        max_retries=3,
    )
    with pytest.raises(JevUnavailableError):
        client.score_alert(SAMPLE_STATE)

    assert call_count == 1  # not retried -- a malformed 200 body is not a transient failure


def test_connection_error_is_retried() -> None:
    call_count = 0
    body = _system_one_body()

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise httpx2.ConnectError("connection refused", request=request)
        return httpx2.Response(200, json=body)

    sleeps: list[float] = []
    client = JevClient(
        api_key="test-key",
        transport=httpx2.MockTransport(handler),
        sleep=sleeps.append,
        backoff_initial=0.01,
    )
    decision = client.score_alert(SAMPLE_STATE)

    assert call_count == 2
    assert len(sleeps) == 1
    assert decision.triage_verdict == "true_positive"
