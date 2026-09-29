"""Tests for services/notifier/slack.py. No real network calls - all HTTP is
faked via _fakes.FakeClient / patch_client_sequence."""

import httpx

import _http
import slack
from _fakes import FakeClient, FakeResponse, patch_client_sequence


def test_not_configured_no_arg_no_env(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    result = slack.send_slack_notification("alert-1", "summary", "high", "true_positive")
    assert result.sent is False
    assert result.skipped_reason == "SLACK_WEBHOOK_URL not configured"
    assert result.error is None


def test_not_configured_empty_string_env(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "")
    result = slack.send_slack_notification("alert-1", "summary", "high", "true_positive")
    assert result.sent is False
    assert result.skipped_reason == "SLACK_WEBHOOK_URL not configured"


def test_explicit_arg_wins_over_env(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/env-url")
    client = FakeClient(response=FakeResponse(200))
    patch_client_sequence(monkeypatch, _http, [client])

    result = slack.send_slack_notification(
        "alert-1", "summary", "high", "true_positive", webhook_url="https://hooks.slack.test/explicit"
    )

    assert result.sent is True
    url, _payload = client.post_calls[0]
    assert url == "https://hooks.slack.test/explicit"


def test_happy_path_200(monkeypatch):
    client = FakeClient(response=FakeResponse(200))
    patch_client_sequence(monkeypatch, _http, [client])

    result = slack.send_slack_notification(
        "alert-42", "brute force detected", "critical", "true_positive", webhook_url="https://hooks.slack.test/x"
    )

    assert result.sent is True
    assert result.status_code == 200
    assert result.error is None
    assert result.skipped_reason is None
    assert len(client.post_calls) == 1
    _url, payload = client.post_calls[0]
    assert "text" in payload
    assert "alert-42" in payload["text"]
    assert "blocks" in payload
    block_text = str(payload["blocks"])
    assert "alert-42" in block_text
    assert "true_positive" in block_text
    assert "critical" in block_text


def test_soft_fail_4xx_no_retry(monkeypatch):
    client = FakeClient(response=FakeResponse(400, "invalid_payload"))
    patch_client_sequence(monkeypatch, _http, [client])

    result = slack.send_slack_notification(
        "alert-1", "summary", "high", "true_positive", webhook_url="https://hooks.slack.test/x"
    )

    assert result.sent is False
    assert result.skipped_reason is None
    assert result.error is not None
    assert result.status_code == 400
    assert len(client.post_calls) == 1  # no retry on 4xx


def test_soft_fail_5xx_exhausted_retry(monkeypatch):
    clients = [FakeClient(response=FakeResponse(500)), FakeClient(response=FakeResponse(500))]
    patch_client_sequence(monkeypatch, _http, clients)

    result = slack.send_slack_notification(
        "alert-1", "summary", "high", "true_positive", webhook_url="https://hooks.slack.test/x"
    )

    assert result.sent is False
    assert result.status_code == 500
    assert result.error is not None
    assert sum(len(c.post_calls) for c in clients) == 2  # retried once, then gave up


def test_recovers_on_second_attempt_after_5xx(monkeypatch):
    clients = [FakeClient(response=FakeResponse(502)), FakeClient(response=FakeResponse(200))]
    patch_client_sequence(monkeypatch, _http, clients)

    result = slack.send_slack_notification(
        "alert-1", "summary", "high", "true_positive", webhook_url="https://hooks.slack.test/x"
    )

    assert result.sent is True
    assert result.status_code == 200


def test_connection_error_exhausted_retry(monkeypatch):
    exc = httpx.ConnectError("connection refused")
    clients = [FakeClient(exc=exc), FakeClient(exc=exc)]
    patch_client_sequence(monkeypatch, _http, clients)

    result = slack.send_slack_notification(
        "alert-1", "summary", "high", "true_positive", webhook_url="https://hooks.slack.test/x"
    )

    assert result.sent is False
    assert result.skipped_reason is None
    assert "ConnectError" in result.error
