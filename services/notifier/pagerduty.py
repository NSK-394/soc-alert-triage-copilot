"""PagerDuty Events API v2 notification client.

See docs/architecture.md §2 and §9: this fires when the policy engine's
auto_escalate action list includes "page_pagerduty". PAGERDUTY_API_KEY is
expected to be empty in local dev until a real PagerDuty account is set up
(§11) - that is a normal, expected state, not an error.

Note on naming: PagerDuty calls the value used here a "routing key" (shown
as "Integration Key" in their UI). This repo's env var is named
PAGERDUTY_API_KEY for historical/.env reasons - that's fixed elsewhere, so
this module just reads it and uses it as the routing key without renaming
the env var.
"""

from __future__ import annotations

import logging
import os

from dotenv import load_dotenv

from _http import post_with_bounded_retry
from models import NotifyResult

load_dotenv()

logger = logging.getLogger(__name__)

PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

# This project's 4-level severity scale mapped onto PagerDuty's own
# Events API v2 severity enum ("critical" | "error" | "warning" | "info").
SEVERITY_TO_PAGERDUTY = {
    "critical": "critical",
    "high": "error",
    "low": "warning",
    "informational": "info",
}


def page_pagerduty(
    alert_id: str,
    summary: str,
    severity: str,
    source: str = "soc-triage-copilot",
    routing_key: str | None = None,
    jev_verdict: str | None = None,
) -> NotifyResult:
    """Trigger a PagerDuty incident via the Events API v2.

    Resolution order for the routing key: explicit `routing_key` argument
    wins (useful for tests and a future per-alert override), otherwise
    falls back to the PAGERDUTY_API_KEY env var.

    `dedup_key` is set to `alert_id` so repeated triggers for the same
    alert dedupe/update the existing incident instead of spamming new ones.

    `jev_verdict` is optional and, when given, is included in
    `custom_details` alongside `alert_id` for on-call context. It is
    appended after the originally-specified parameters (rather than
    inserted earlier) so existing positional call sites are unaffected.

    Never raises: a PagerDuty outage or missing config must never block the
    policy/escalation pipeline that calls this.
    """
    resolved_key = routing_key if routing_key is not None else os.getenv("PAGERDUTY_API_KEY")

    if not resolved_key:
        logger.warning(
            "PAGERDUTY_API_KEY not configured - skipping PagerDuty page for alert %s",
            alert_id,
        )
        return NotifyResult(sent=False, skipped_reason="PAGERDUTY_API_KEY not configured")

    pd_severity = SEVERITY_TO_PAGERDUTY.get(severity, "info")

    payload = {
        "routing_key": resolved_key,
        "event_action": "trigger",
        "dedup_key": alert_id,
        "payload": {
            "summary": summary,
            "source": source,
            "severity": pd_severity,
            "custom_details": {
                "alert_id": alert_id,
                "jev_verdict": jev_verdict,
            },
        },
    }

    outcome = post_with_bounded_retry(PAGERDUTY_EVENTS_URL, payload)

    if outcome.ok:
        return NotifyResult(sent=True, status_code=outcome.status_code)

    logger.error("PagerDuty page failed for alert %s: %s", alert_id, outcome.error)
    return NotifyResult(sent=False, skipped_reason=None, error=outcome.error, status_code=outcome.status_code)
