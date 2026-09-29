"""Shared fake HTTP client used by test_slack.py and test_pagerduty.py.

Avoids any real network I/O: monkeypatches `_http.httpx.Client` with a
stand-in that records calls and returns/raises exactly what a test wants,
so retries and status-code branches can be exercised deterministically.
"""

from __future__ import annotations


class FakeResponse:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class FakeClient:
    """One fake httpx.Client instance, good for exactly one `with ... as c: c.post(...)`."""

    def __init__(self, response: FakeResponse | None = None, exc: Exception | None = None):
        self._response = response
        self._exc = exc
        self.post_calls: list[tuple[str, dict]] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def post(self, url: str, json: dict):
        self.post_calls.append((url, json))
        if self._exc is not None:
            raise self._exc
        return self._response


def patch_client_sequence(monkeypatch, http_module, clients: list[FakeClient]) -> None:
    """Make successive `httpx.Client(...)` calls in http_module return each of `clients` in order.

    post_with_bounded_retry instantiates a fresh httpx.Client per attempt, so
    a retry test passes one FakeClient per expected attempt.
    """
    it = iter(clients)

    def fake_client(*args, **kwargs):
        return next(it)

    monkeypatch.setattr(http_module.httpx, "Client", fake_client)
