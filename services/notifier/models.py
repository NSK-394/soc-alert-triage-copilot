"""Shared result type for the notifier service's outbound notification clients."""

from __future__ import annotations

from pydantic import BaseModel


class NotifyResult(BaseModel):
    """Outcome of a single notification attempt.

    Exactly one of the following should generally be true:
    - sent=True: the notification was accepted by the provider.
    - skipped_reason is set: the client is not configured (e.g. missing
      webhook URL / routing key), so nothing was sent and nothing failed.
    - error is set: the client attempted delivery but it failed (bad
      request, exhausted retries, connection error, etc).

    This model is returned by every public function in this service and is
    never raised as an exception — a notification failure must never be
    allowed to crash or block the caller's pipeline.
    """

    sent: bool
    skipped_reason: str | None = None
    error: str | None = None
    status_code: int | None = None
