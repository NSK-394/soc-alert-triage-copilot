"""Unit tests for the pure/testable pieces of replay.py:

  - compute_sleep_seconds (rate-limiter sleep-time computation)
  - parse_jsonl_line (line parsing / validation)
  - is_retryable_status / is_retryable_exception (retry-eligibility logic)
  - send_record (HTTP send + bounded retry, with the actual `requests.Session`
    mocked out and `sleep_func` stubbed so no real network calls or wall-clock
    sleeping ever happen)

No real ingest-api instance is required to run these tests.
"""

from unittest import mock

import pytest
import requests

from replay import (
    SendResult,
    compute_sleep_seconds,
    is_retryable_exception,
    is_retryable_status,
    parse_jsonl_line,
    send_record,
)


# --------------------------------------------------------------------------
# compute_sleep_seconds
# --------------------------------------------------------------------------


class TestComputeSleepSeconds:
    def test_first_record_never_sleeps(self):
        assert compute_sleep_seconds(rate=10.0, sent_count=0, elapsed=0.0) == 0.0

    def test_sleeps_to_hit_target_rate_when_on_schedule(self):
        # At 10/sec, the 2nd record (sent_count=1) should ideally go out at
        # t=0.1s. If no time has elapsed yet, sleep exactly 0.1s.
        assert compute_sleep_seconds(rate=10.0, sent_count=1, elapsed=0.0) == pytest.approx(0.1)

    def test_no_sleep_when_already_behind_schedule(self):
        # We've already spent longer than the ideal schedule requires (e.g.
        # slow HTTP calls) -- never sleep to "catch up" with negative time.
        assert compute_sleep_seconds(rate=10.0, sent_count=1, elapsed=5.0) == 0.0

    def test_partial_sleep_when_partway_through_schedule(self):
        # 5 records already sent at rate=10/sec => ideal elapsed = 0.5s.
        # Only 0.3s has actually elapsed => sleep the remaining 0.2s.
        assert compute_sleep_seconds(rate=10.0, sent_count=5, elapsed=0.3) == pytest.approx(0.2)

    def test_zero_rate_disables_throttling(self):
        assert compute_sleep_seconds(rate=0.0, sent_count=100, elapsed=0.0) == 0.0

    def test_negative_rate_disables_throttling(self):
        assert compute_sleep_seconds(rate=-5.0, sent_count=100, elapsed=0.0) == 0.0

    def test_high_rate_yields_small_sleep(self):
        assert compute_sleep_seconds(rate=1000.0, sent_count=1, elapsed=0.0) == pytest.approx(0.001)

    def test_never_returns_negative(self):
        assert compute_sleep_seconds(rate=1.0, sent_count=0, elapsed=999.0) >= 0.0


# --------------------------------------------------------------------------
# parse_jsonl_line
# --------------------------------------------------------------------------


class TestParseJsonlLine:
    def test_valid_record(self):
        line = '{"source": "guide_replay", "external_id": "a1", "incident_id": null, "raw": {"x": 1}, "normalized": {}, "ground_truth_label": "true_positive"}\n'
        record, error = parse_jsonl_line(line, 1)
        assert error is None
        assert record["source"] == "guide_replay"
        assert record["raw"] == {"x": 1}

    def test_blank_line_is_silently_skipped(self):
        record, error = parse_jsonl_line("\n", 2)
        assert record is None
        assert error is None

    def test_whitespace_only_line_is_silently_skipped(self):
        record, error = parse_jsonl_line("   \t  \n", 3)
        assert record is None
        assert error is None

    def test_malformed_json_reports_line_number(self):
        record, error = parse_jsonl_line('{"source": "guide_replay", "raw": {\n', 4)
        assert record is None
        assert error is not None
        assert "line 4" in error
        assert "malformed JSON" in error

    def test_valid_json_but_not_an_object_is_rejected(self):
        record, error = parse_jsonl_line("[1, 2, 3]\n", 5)
        assert record is None
        assert error is not None
        assert "line 5" in error
        assert "not a JSON object" in error

    def test_json_scalar_is_rejected(self):
        record, error = parse_jsonl_line('"just a string"\n', 6)
        assert record is None
        assert error is not None
        assert "line 6" in error

    def test_missing_source_key_is_rejected(self):
        record, error = parse_jsonl_line('{"raw": {}}\n', 7)
        assert record is None
        assert error is not None
        assert "missing required key" in error
        assert "'source'" in error

    def test_missing_raw_key_is_rejected(self):
        record, error = parse_jsonl_line('{"source": "guide_replay"}\n', 8)
        assert record is None
        assert error is not None
        assert "missing required key" in error
        assert "'raw'" in error

    def test_missing_both_required_keys_is_rejected(self):
        record, error = parse_jsonl_line('{"foo": "bar"}\n', 9)
        assert record is None
        assert error is not None
        assert "'source'" in error and "'raw'" in error

    def test_extra_unknown_fields_are_tolerated(self):
        line = '{"source": "guide_replay", "raw": {}, "some_future_field": 42}\n'
        record, error = parse_jsonl_line(line, 10)
        assert error is None
        assert record["some_future_field"] == 42


# --------------------------------------------------------------------------
# is_retryable_status / is_retryable_exception
# --------------------------------------------------------------------------


class TestRetryEligibility:
    @pytest.mark.parametrize("status", [500, 502, 503, 504, 599])
    def test_5xx_is_retryable(self, status):
        assert is_retryable_status(status) is True

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422, 429, 499])
    def test_4xx_is_not_retryable(self, status):
        assert is_retryable_status(status) is False

    @pytest.mark.parametrize("status", [200, 201, 204, 301, 302])
    def test_2xx_3xx_is_not_retryable(self, status):
        assert is_retryable_status(status) is False

    def test_connection_error_is_retryable(self):
        assert is_retryable_exception(requests.exceptions.ConnectionError("boom")) is True

    def test_timeout_is_retryable(self):
        assert is_retryable_exception(requests.exceptions.Timeout("slow")) is True

    def test_read_timeout_is_retryable(self):
        assert is_retryable_exception(requests.exceptions.ReadTimeout("slow")) is True

    def test_missing_schema_is_not_retryable(self):
        # A malformed URL is a configuration bug, not a transient failure.
        assert is_retryable_exception(requests.exceptions.MissingSchema("bad url")) is False

    def test_generic_request_exception_is_not_retryable(self):
        assert is_retryable_exception(requests.exceptions.RequestException("?")) is False


# --------------------------------------------------------------------------
# send_record (HTTP mocked; sleep_func stubbed to a no-op)
# --------------------------------------------------------------------------


def _response(status_code, text=""):
    resp = mock.Mock()
    resp.status_code = status_code
    resp.text = text
    return resp


class TestSendRecord:
    def test_succeeds_on_first_try_200(self):
        session = mock.Mock()
        session.post.return_value = _response(200)
        result = send_record(session, "http://x/replay", {"source": "a", "raw": {}}, timeout=5.0)
        assert result == SendResult(ok=True, status_code=200, error=None, attempts=1)
        assert session.post.call_count == 1

    def test_succeeds_on_first_try_201(self):
        session = mock.Mock()
        session.post.return_value = _response(201)
        result = send_record(session, "http://x/replay", {"source": "a", "raw": {}}, timeout=5.0)
        assert result.ok is True
        assert result.status_code == 201

    def test_retries_on_5xx_then_succeeds(self):
        session = mock.Mock()
        session.post.side_effect = [_response(503, "unavailable"), _response(200)]
        sleep_calls = []
        result = send_record(
            session,
            "http://x/replay",
            {"source": "a", "raw": {}},
            timeout=5.0,
            sleep_func=sleep_calls.append,
        )
        assert result.ok is True
        assert result.attempts == 2
        assert session.post.call_count == 2
        assert len(sleep_calls) == 1  # backed off exactly once

    def test_does_not_retry_on_4xx(self):
        session = mock.Mock()
        session.post.return_value = _response(422, "bad record")
        sleep_calls = []
        result = send_record(
            session,
            "http://x/replay",
            {"source": "a", "raw": {}},
            timeout=5.0,
            sleep_func=sleep_calls.append,
        )
        assert result.ok is False
        assert result.status_code == 422
        assert result.attempts == 1
        assert session.post.call_count == 1
        assert sleep_calls == []  # never slept -- no retry attempted

    def test_exhausts_retries_on_persistent_5xx(self):
        session = mock.Mock()
        session.post.return_value = _response(500, "server error")
        result = send_record(
            session,
            "http://x/replay",
            {"source": "a", "raw": {}},
            timeout=5.0,
            max_attempts=3,
            sleep_func=lambda s: None,
        )
        assert result.ok is False
        assert result.status_code == 500
        assert result.attempts == 3
        assert session.post.call_count == 3

    def test_retries_on_connection_error_then_succeeds(self):
        session = mock.Mock()
        session.post.side_effect = [requests.exceptions.ConnectionError("boom"), _response(200)]
        result = send_record(
            session,
            "http://x/replay",
            {"source": "a", "raw": {}},
            timeout=5.0,
            sleep_func=lambda s: None,
        )
        assert result.ok is True
        assert result.attempts == 2

    def test_does_not_retry_on_non_transient_exception(self):
        session = mock.Mock()
        session.post.side_effect = requests.exceptions.MissingSchema("bad url")
        sleep_calls = []
        result = send_record(
            session,
            "http://x/replay",
            {"source": "a", "raw": {}},
            timeout=5.0,
            sleep_func=sleep_calls.append,
        )
        assert result.ok is False
        assert result.attempts == 1
        assert session.post.call_count == 1
        assert sleep_calls == []

    def test_exhausts_retries_on_persistent_timeout(self):
        session = mock.Mock()
        session.post.side_effect = requests.exceptions.Timeout("slow")
        result = send_record(
            session,
            "http://x/replay",
            {"source": "a", "raw": {}},
            timeout=5.0,
            max_attempts=3,
            sleep_func=lambda s: None,
        )
        assert result.ok is False
        assert result.attempts == 3
        assert session.post.call_count == 3

    def test_backoff_durations_grow_exponentially(self):
        session = mock.Mock()
        session.post.side_effect = [
            _response(503),
            _response(503),
            _response(200),
        ]
        sleep_calls = []
        send_record(
            session,
            "http://x/replay",
            {"source": "a", "raw": {}},
            timeout=5.0,
            max_attempts=3,
            backoff_base=0.5,
            sleep_func=sleep_calls.append,
        )
        assert sleep_calls == [0.5, 1.0]

    def test_sends_record_as_json_body_to_correct_url(self):
        session = mock.Mock()
        session.post.return_value = _response(200)
        record = {"source": "guide_replay", "raw": {"foo": "bar"}}
        send_record(session, "http://example.com/replay", record, timeout=7.5)
        session.post.assert_called_once_with("http://example.com/replay", json=record, timeout=7.5)
