"""Internal HTTP helper shared by the Slack and PagerDuty clients.

Not a public API of this service - just the bounded-retry POST logic both
clients need, factored out to avoid duplicating it. This is plumbing, not a
notification-channel abstraction: it knows nothing about Slack or
PagerDuty payload shapes.
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


class HttpOutcome:
    """Result of attempting a POST, before it's translated into a NotifyResult."""

    def __init__(
        self,
        *,
        ok: bool,
        status_code: int | None = None,
        response: httpx.Response | None = None,
        error: str | None = None,
    ) -> None:
        self.ok = ok
        self.status_code = status_code
        self.response = response
        self.error = error


def post_with_bounded_retry(
    url: str,
    json_payload: dict,
    *,
    max_attempts: int = 2,
    timeout: float = 5.0,
) -> HttpOutcome:
    """POST json_payload to url, retrying only on connection errors or 5xx.

    4xx responses are never retried - they indicate a bad payload or a
    dead/invalid webhook/routing key, which a retry cannot fix.
    """
    last_error: str | None = None
    last_response: httpx.Response | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(url, json=json_payload)
        except httpx.RequestError as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "Notification POST to %s failed (attempt %d/%d): %s",
                url,
                attempt,
                max_attempts,
                last_error,
            )
            if attempt < max_attempts:
                continue
            return HttpOutcome(ok=False, error=last_error)

        if 200 <= response.status_code < 300:
            return HttpOutcome(ok=True, status_code=response.status_code, response=response)

        if response.status_code >= 500:
            last_response = response
            logger.warning(
                "Notification POST to %s got server error %d (attempt %d/%d)",
                url,
                response.status_code,
                attempt,
                max_attempts,
            )
            if attempt < max_attempts:
                continue
            return HttpOutcome(
                ok=False,
                status_code=response.status_code,
                response=response,
                error=f"HTTP {response.status_code} after {max_attempts} attempts",
            )

        # 4xx: soft-fail immediately, no retry.
        logger.error(
            "Notification POST to %s rejected with %d: %s",
            url,
            response.status_code,
            response.text[:500],
        )
        return HttpOutcome(
            ok=False,
            status_code=response.status_code,
            response=response,
            error=f"HTTP {response.status_code}: {response.text[:500]}",
        )

    # Unreachable, but keeps type checkers happy.
    return HttpOutcome(ok=False, status_code=None, response=last_response, error=last_error)
