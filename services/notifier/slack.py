"""Slack incoming-webhook notification client.

See docs/architecture.md §2 and §9: this fires when the policy engine's
auto_escalate action list includes "notify_slack". SLACK_WEBHOOK_URL is
expected to be empty in local dev until a real Slack workspace is set up
(§11) - that is a normal, expected state, not an error.
"""

from __future__ import annotations

import logging
import os

from dotenv import load_dotenv

from _http import post_with_bounded_retry
from models import NotifyResult

load_dotenv()

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":warning:",
    "low": ":large_yellow_circle:",
    "informational": ":information_source:",
}


def send_slack_notification(
    alert_id: str,
    summary: str,
    severity: str,
    jev_verdict: str,
    webhook_url: str | None = None,
) -> NotifyResult:
    """Post an alert notification to Slack via an incoming webhook.

    Resolution order for the webhook URL: explicit `webhook_url` argument
    wins (useful for tests and a future per-alert override), otherwise
    falls back to the SLACK_WEBHOOK_URL env var.

    Never raises: a Slack outage or missing config must never block the
    policy/escalation pipeline that calls this.
    """
    resolved_url = webhook_url if webhook_url is not None else os.getenv("SLACK_WEBHOOK_URL")

    if not resolved_url:
        logger.warning(
            "SLACK_WEBHOOK_URL not configured - skipping Slack notification for alert %s",
            alert_id,
        )
        return NotifyResult(sent=False, skipped_reason="SLACK_WEBHOOK_URL not configured")

    emoji = _SEVERITY_EMOJI.get(severity, ":question:")
    text = f"{emoji} [{severity.upper()}] Alert {alert_id} - {jev_verdict} - {summary}"

    payload = {
        "text": text,
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} SOC Alert - {severity.upper()}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Alert ID:*\n{alert_id}"},
                    {"type": "mrkdwn", "text": f"*Jev Verdict:*\n{jev_verdict}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:* {summary}"},
            },
        ],
    }

    outcome = post_with_bounded_retry(resolved_url, payload)

    if outcome.ok:
        return NotifyResult(sent=True, status_code=outcome.status_code)

    logger.error("Slack notification failed for alert %s: %s", alert_id, outcome.error)
    return NotifyResult(sent=False, skipped_reason=None, error=outcome.error, status_code=outcome.status_code)
