"""Tests for services/notifier/pagerduty.py. No real network calls - all HTTP
is faked via _fakes.FakeClient / patch_client_sequence."""

import httpx
import pytest

import _http
import pagerduty
from _fakes import FakeClient, FakeResponse, patch_client_sequence


def test_not_configured_no_arg_no_env(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_API_KEY", raising=False)
    result = pagerduty.page_pagerduty("alert-1", "summary", "critical")
    assert result.sent is False
    assert result.skipped_reason == "PAGERDUTY_API_KEY not configured"
    assert result.error is None


def test_not_configured_empty_string_env(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_KEY", "")
    result = pagerduty.page_pagerduty("alert-1", "summary", "critical")
    assert result.sent is False
    assert result.skipped_reason == "PAGERDUTY_API_KEY not configured"


def test_explicit_arg_wins_over_env(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_KEY", "env-routing-key")
    client = FakeClient(response=FakeResponse(202))
    patch_client_sequence(monkeypatch, _http, [client])

    result = pagerduty.page_pagerduty("alert-1", "summary", "critical", routing_key="explicit-routing-key")

    assert result.sent is True
    _url, payload = client.post_calls[0]
    assert payload["routing_key"] == "explicit-routing-key"


def test_happy_path_and_payload_shape(monkeypatch):
    client = FakeClient(response=FakeResponse(202))
    patch_client_sequence(monkeypatch, _http, [client])

    result = pagerduty.page_pagerduty(
        "alert-123",
        "SSH brute force on db-prod-02",
        "critical",
        routing_key="RKEY",
        jev_verdict="true_positive",
    )

    assert result.sent is True
    assert result.status_code == 202
    url, payload = client.post_calls[0]
    assert url == pagerduty.PAGERDUTY_EVENTS_URL
    assert payload["routing_key"] == "RKEY"
    assert payload["event_action"] == "trigger"
    assert payload["dedup_key"] == "alert-123"
    assert payload["payload"]["summary"] == "SSH brute force on db-prod-02"
    assert payload["payload"]["source"] == "soc-triage-copilot"
    assert payload["payload"]["severity"] == "critical"
    assert payload["payload"]["custom_details"]["alert_id"] == "alert-123"
    assert payload["payload"]["custom_details"]["jev_verdict"] == "true_positive"


@pytest.mark.parametrize(
    "project_severity,expected_pd_severity",
    [
        ("critical", "critical"),
        ("high", "error"),
        ("low", "warning"),
        ("informational", "info"),
    ],
)
def test_severity_mapping(monkeypatch, project_severity, expected_pd_severity):
    client = FakeClient(response=FakeResponse(202))
    patch_client_sequence(monkeypatch, _http, [client])

    pagerduty.page_pagerduty("alert-1", "summary", project_severity, routing_key="RKEY")

    _url, payload = client.post_calls[0]
    assert payload["payload"]["severity"] == expected_pd_severity


def test_severity_mapping_constant_is_exact():
    assert pagerduty.SEVERITY_TO_PAGERDUTY == {
        "critical": "critical",
        "high": "error",
        "low": "warning",
        "informational": "info",
    }


def test_unknown_severity_defaults_to_info(monkeypatch):
    client = FakeClient(response=FakeResponse(202))
    patch_client_sequence(monkeypatch, _http, [client])

    pagerduty.page_pagerduty("alert-1", "summary", "not-a-real-severity", routing_key="RKEY")

    _url, payload = client.post_calls[0]
    assert payload["payload"]["severity"] == "info"


def test_soft_fail_4xx_no_retry(monkeypatch):
    client = FakeClient(response=FakeResponse(400, "invalid routing key"))
    patch_client_sequence(monkeypatch, _http, [client])

    result = pagerduty.page_pagerduty("alert-1", "summary", "high", routing_key="RKEY")

    assert result.sent is False
    assert result.skipped_reason is None
    assert result.status_code == 400
    assert len(client.post_calls) == 1


def test_soft_fail_5xx_exhausted_retry(monkeypatch):
    clients = [FakeClient(response=FakeResponse(503)), FakeClient(response=FakeResponse(503))]
    patch_client_sequence(monkeypatch, _http, clients)

    result = pagerduty.page_pagerduty("alert-1", "summary", "high", routing_key="RKEY")

    assert result.sent is False
    assert result.status_code == 503
    assert sum(len(c.post_calls) for c in clients) == 2


def test_connection_error_exhausted_retry(monkeypatch):
    exc = httpx.ConnectError("connection refused")
    clients = [FakeClient(exc=exc), FakeClient(exc=exc)]
    patch_client_sequence(monkeypatch, _http, clients)

    result = pagerduty.page_pagerduty("alert-1", "summary", "high", routing_key="RKEY")

    assert result.sent is False
    assert "ConnectError" in result.error
