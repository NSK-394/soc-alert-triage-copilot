"""The live pipeline: ingest -> features -> Jev -> policy -> notifier -> Tier-2
(docs/architecture.md §2, §12 Phase C task 3, extended for Phase D task 2's Tier-2
brief wiring).

`run_pipeline(pool, alert_id)` is invoked by the RQ worker (services/tier2-worker/
rq_worker.py's `process_alert`) for every alert enqueued by
`services/ingest-api/job_queue.py` -- which only happens for a FRESH `/webhook/wazuh`
insert (never for `/replay`; see job_queue.py's docstring for why that separation is
safety-critical).

Import setup for hyphenated sibling service directories
---------------------------------------------------------
This module reaches into several sibling `services/*` directories that cannot be
imported with a normal dotted import because their directory names contain a hyphen
(`import services.feature-builder` is a syntax error). This repo's established
convention (see `data/converters/guide_to_state.py`, and every hyphenated service's
own `tests/conftest.py`) is: add the directory to `sys.path`, then import its modules
as flat top-level names. That's what the block below does, for:
  - services/feature-builder  (derived_fields.off_hours)
  - services/jev-client       (client.JevClient/JevUnavailableError)
  - services/policy-engine    (evaluator.load_policy/evaluate)
  - services/notifier         (slack.send_slack_notification, pagerduty.page_pagerduty)
  - services/tier2-worker     (worker.generate_brief_for_alert/BudgetExceededError/
                                InvalidCitationError, providers.resolve_provider)

MVP limitation, stated once here (also noted inline at the `derived` fields below):
this repo has no real historical auth-event store, IP reputation feed, or asset
criticality inventory wired up yet. Every `derived` field except `off_hours` (which
is genuinely computable from the alert's own timestamp) is therefore left at the
same conservative, documented default `data/converters/guide_to_state.py` uses for
GUIDE-derived alerts: 0 / false / 0 / "unknown" / "unknown" / 0.0 / 0. This is a
known, intentional gap, not an oversight -- see docs/architecture.md §4's
`derived` schema and §7's converter notes for the same defaults applied elsewhere.
"""
from __future__ import annotations

import logging
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import asyncpg

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SERVICES_DIR = _REPO_ROOT / "services"
for _service_dir_name in ("feature-builder", "jev-client", "policy-engine", "notifier", "tier2-worker"):
    _service_dir = _SERVICES_DIR / _service_dir_name
    if str(_service_dir) not in sys.path:
        sys.path.insert(0, str(_service_dir))

from derived_fields import off_hours  # noqa: E402  (feature-builder)
from client import JevClient, JevUnavailableError  # noqa: E402  (jev-client)
from evaluator import evaluate, load_policy  # noqa: E402  (policy-engine)
from slack import send_slack_notification  # noqa: E402  (notifier)
from pagerduty import page_pagerduty  # noqa: E402  (notifier)
from worker import (  # noqa: E402  (tier2-worker)
    BudgetExceededError,
    InvalidCitationError,
    generate_brief_for_alert,
)
from providers import resolve_provider  # noqa: E402  (tier2-worker)

logger = logging.getLogger(__name__)

# Policy YAML path (docs/architecture.md §8). Loaded lazily and cached at module
# level -- it's a small, rarely-changing file; re-reading it from disk on every
# single alert would be wasteful for no real benefit.
_POLICY_PATH = _SERVICES_DIR / "policy-engine" / "policy" / "v1.yaml"
_policy_cache: dict | None = None

# docs/architecture.md §5: "Endpoint: POST https://api.typesafe.ai/v1/systemone,
# model route jev-latest" -- this is a fixed identifier for the `costs`/logging
# rows below, not something JevClient/JevDecision exposes as an attribute.
_JEV_MODEL_NAME = "jev-latest"


_JEV_DAILY_CALL_CAP_DEFAULT = 10_000


async def _jev_daily_call_count(pool: asyncpg.Pool) -> int:
    return await pool.fetchval(
        "SELECT COUNT(*) FROM costs WHERE call_type = 'jev' AND created_at::date = CURRENT_DATE"
    )


async def _jev_daily_cap_exceeded(pool: asyncpg.Pool) -> bool:
    """A security audit flagged that Jev/Tier-1 calls have no daily cap -- only
    jev-client's fixed request-rate limiter (services/jev-client/rate_limiter.py),
    which throttles but never stops sustained abuse (e.g. via an unauthenticated
    /webhook/wazuh before WAZUH_WEBHOOK_SECRET is configured). Tier-2 already has
    budget_guard.py's daily $ ceiling; this mirrors that pattern for Jev as a call-
    count cap rather than a $ ceiling, since Jev calls are currently costed at 0.0
    (docs/architecture.md documents no per-token Jev price -- see
    _insert_jev_decision_and_cost's comment), so a USD ceiling would be meaningless.
    """
    cap = int(os.environ.get("JEV_DAILY_CALL_CAP", _JEV_DAILY_CALL_CAP_DEFAULT))
    count = await _jev_daily_call_count(pool)
    return count >= cap


def _get_policy() -> dict:
    global _policy_cache
    if _policy_cache is None:
        _policy_cache = load_policy(str(_POLICY_PATH))
    return _policy_cache


def _parse_wazuh_timestamp(raw_timestamp: str) -> datetime:
    """Parse a Wazuh alert's `timestamp` field into a tz-aware UTC datetime.

    Real Wazuh alerts (see infra/wazuh/scenarios/*.json) use
    "%Y-%m-%dT%H:%M:%S.%f%z", e.g. "2026-09-20T03:12:44.118+0000". Python 3.11's
    `datetime.fromisoformat` accepts that format (and most other real-world ISO 8601
    variants, including a trailing "Z") directly, so it's tried first; the exact
    fixture format is the documented fallback for any older-Python edge case.
    """
    try:
        return datetime.fromisoformat(raw_timestamp)
    except ValueError:
        pass
    return datetime.strptime(raw_timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")


def build_state_object_from_wazuh(raw: dict[str, Any]) -> dict[str, Any]:
    """Map a raw Wazuh alert payload (infra/wazuh/scenarios/*.json shape) into the
    Jev state object from docs/architecture.md §4.

    Field mapping (judgment calls, documented once here):
      - rule.id            -> alert.rule_id (stringified; "unknown" if absent --
                               a real Wazuh alert always has this, so this is a
                               defensive fallback, not an expected path)
      - rule.description   -> alert.rule_description ("unknown" if absent)
      - rule.level         -> alert.rule_level (int; 0 if absent/non-numeric)
      - rule.mitre.id      -> alert.mitre_hint. ONLY this field is used -- rule.groups
                               tags (e.g. "authentication_failures", "pci_dss_10.2.4")
                               are compliance/categorization labels, not MITRE
                               technique IDs, and mapping them in would be
                               fabricating a mitre_hint the alert doesn't actually
                               assert. Empty list if rule.mitre.id isn't present,
                               never guessed.
      - timestamp          -> alert.timestamp_utc, passed through verbatim (Wazuh's
                               own "+0000"-offset style; JevStateObject only requires
                               a string, not a specific format).
      - data.srcip          -> entities.src_ip
      - data.srcuser         (falling back to data.dstuser, then data.user, in that
                               order -- ssh_brute_force/sudo_abuse carry srcuser;
                               new_listening_service carries neither, so this
                               legitimately resolves to None for that scenario)
                              -> entities.user
      - agent.name          -> entities.host
      - full_log            -> untrusted_evidence.raw_log_excerpt (the one place
                               genuinely attacker-influenced text lives, per
                               docs/architecture.md §4/§10 -- passed through
                               untouched, never parsed/executed/used for control
                               flow here).
    """
    rule = raw.get("rule") or {}
    agent = raw.get("agent") or {}
    data = raw.get("data") or {}

    rule_id = str(rule["id"]) if rule.get("id") is not None else "unknown"
    rule_description = rule.get("description") or "unknown"
    try:
        rule_level = int(rule.get("level"))
    except (TypeError, ValueError):
        rule_level = 0

    mitre_ids = (rule.get("mitre") or {}).get("id") or []
    mitre_hint = [str(technique_id) for technique_id in mitre_ids]

    timestamp_raw = raw.get("timestamp")
    if not timestamp_raw:
        raise ValueError("wazuh alert has no 'timestamp' field; cannot compute off_hours")
    reference_time = _parse_wazuh_timestamp(timestamp_raw)

    src_ip = data.get("srcip")
    user = data.get("srcuser") or data.get("dstuser") or data.get("user")
    host = agent.get("name")

    raw_log_excerpt = raw.get("full_log") or ""

    return {
        "alert": {
            "source": "wazuh",
            "rule_id": rule_id,
            "rule_description": rule_description,
            "rule_level": rule_level,
            "mitre_hint": mitre_hint,
            "timestamp_utc": timestamp_raw,
        },
        "entities": {
            "src_ip": src_ip,
            "user": user,
            "host": host,
        },
        "derived": {
            # Genuinely computed -- pure calendar arithmetic on the alert's real
            # timestamp (docs/architecture.md §5: counting/date arithmetic must
            # always be computed in code, never left for Jev).
            "off_hours": off_hours(reference_time),
            # MVP limitation (see module docstring): no real historical auth-event
            # store, IP reputation feed, or asset-criticality inventory is wired up
            # yet. These are the same conservative, documented defaults
            # data/converters/guide_to_state.py uses for GUIDE-derived alerts --
            # NOT fabricated values.
            "failed_auth_10m": 0,
            "successful_auth_after_failures": False,
            "src_ip_first_seen_days": 0,
            "src_ip_reputation": "unknown",
            "host_criticality": "unknown",
            "rule_historical_fp_rate": 0.0,
            "similar_alerts_24h": 0,
        },
        "untrusted_evidence": {
            "raw_log_excerpt": raw_log_excerpt,
        },
    }


async def _insert_jev_decision_and_cost(pool: asyncpg.Pool, alert_uuid: uuid.UUID, decision) -> None:
    await pool.execute(
        """
        INSERT INTO jev_decisions (
            alert_id, triage_verdict, is_false_positive_prob, severity, attack_category,
            needs_more_context_prob, business_impact_if_true, confidence_margin,
            raw_response, latency_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        alert_uuid,
        decision.triage_verdict,
        decision.is_false_positive_prob,
        decision.severity,
        decision.attack_category,
        decision.needs_more_context_prob,
        decision.business_impact_if_true,
        decision.confidence_margin,
        decision.raw_response,
        decision.latency_ms,
    )

    # JevDecision itself has no dedicated token-count fields, but the raw SDK
    # response it wraps (typesafe_sdk.SystemOneResponse) DOES carry a real `usage`
    # object (`{"input_tokens": ..., "output_tokens": ...}`), preserved verbatim in
    # `decision.raw_response`. That's real data the client actually returned, not
    # something to invent -- so it's read from there rather than hardcoded to 0.
    # `cost_usd` is genuinely 0.0: docs/architecture.md §6 gives Tier-2 pricing but
    # documents no per-token USD rate for Jev/TypeSafe anywhere, so there is no
    # honest way to price this call; 0.0 reflects "not priced," not "free."
    usage = (decision.raw_response or {}).get("usage") or {}
    tokens_in = usage.get("input_tokens", 0)
    tokens_out = usage.get("output_tokens", 0)
    await pool.execute(
        """
        INSERT INTO costs (alert_id, call_type, provider, model, tokens_in, tokens_out, cost_usd)
        VALUES ($1, 'jev', 'typesafe', $2, $3, $4, $5)
        """,
        alert_uuid,
        _JEV_MODEL_NAME,
        tokens_in,
        tokens_out,
        0.0,
    )


def _build_notification_summary(state: dict[str, Any]) -> str:
    alert_section = state.get("alert") or {}
    entities = state.get("entities") or {}
    rule_description = alert_section.get("rule_description") or "unknown rule"
    host = entities.get("host") or "unknown host"
    src_ip = entities.get("src_ip") or "unknown src_ip"
    return f"{rule_description} on {host} ({src_ip})"


async def _run_pipeline_inner(pool: asyncpg.Pool, alert_id: str) -> None:
    alert_uuid = alert_id if isinstance(alert_id, uuid.UUID) else uuid.UUID(str(alert_id))

    row = await pool.fetchrow(
        """
        SELECT id, source, external_id, incident_id, raw, normalized,
               ground_truth_label, ingested_at
        FROM alerts
        WHERE id = $1
        """,
        alert_uuid,
    )
    if row is None:
        logger.error("pipeline: alert %s not found in alerts table; nothing to do", alert_id)
        return

    alert_row = dict(row)
    raw = alert_row["raw"] or {}
    existing_normalized = alert_row.get("normalized") or {}

    if existing_normalized:
        # Defensive: shouldn't normally happen via /webhook/wazuh (which always
        # inserts normalized={}), but don't crash or clobber real data if it does.
        logger.info(
            "pipeline: alert %s already has non-empty normalized data; skipping re-normalization",
            alert_id,
        )
        state = existing_normalized
    else:
        state = build_state_object_from_wazuh(raw)
        await pool.execute(
            "UPDATE alerts SET normalized = $1 WHERE id = $2",
            state,
            alert_uuid,
        )
    alert_row["normalized"] = state

    # --- Tier 1: Jev ---------------------------------------------------------
    jev_failed = False
    decision = None
    if await _jev_daily_cap_exceeded(pool):
        # Same fail-safe as a real JevUnavailableError: never auto-act without a
        # Jev decision, route to `queued`. Logged distinctly so a spend/abuse
        # investigation can tell "Jev was down" apart from "we hit our own cap".
        jev_failed = True
        logger.error("pipeline: JEV_DAILY_CALL_CAP reached; skipping Jev call for alert %s", alert_id)
    else:
        client = JevClient()
        try:
            try:
                decision = client.score_alert(state)
            except JevUnavailableError as exc:
                # *** FAIL-SAFE CONTRACT (docs/architecture.md §5/§8) ***: never let
                # this propagate, and never auto-close on a Jev failure -- route to
                # `queued` via jev_failed=True below.
                jev_failed = True
                logger.error("pipeline: Jev unavailable for alert %s: %s", alert_id, exc)
        finally:
            client.close()

    if decision is not None:
        await _insert_jev_decision_and_cost(pool, alert_uuid, decision)

    # --- Policy engine ---------------------------------------------------------
    policy = _get_policy()
    derived = state.get("derived") or {}
    host_criticality = derived.get("host_criticality", "unknown")
    rule_id = (state.get("alert") or {}).get("rule_id", "unknown")

    if jev_failed:
        # evaluate() short-circuits on jev_failed=True before touching any other
        # argument (see evaluator.py), so these placeholders are never read.
        outcome = evaluate(
            policy,
            jev_verdict="",
            jev_confidence=0.0,
            jev_severity="informational",
            host_criticality=host_criticality,
            rule_id=rule_id,
            jev_failed=True,
            shadow_mode=False,
        )
    else:
        outcome = evaluate(
            policy,
            jev_verdict=decision.triage_verdict,
            # The policy engine's confidence thresholds are keyed off Jev's own
            # margin/entropy computation, never a single bundled confidence field
            # (docs/architecture.md §5) -- confidence_margin is exactly that field
            # (see client.py: "The overall summary field the policy engine keys
            # off of: triage_verdict's distribution").
            jev_confidence=decision.confidence_margin,
            jev_severity=decision.severity,
            host_criticality=host_criticality,
            rule_id=rule_id,
            jev_failed=False,
            shadow_mode=False,
        )

    await pool.execute(
        """
        INSERT INTO policy_outcomes (alert_id, action, rule_version, reason, shadow_mode)
        VALUES ($1, $2, $3, $4, $5)
        """,
        alert_uuid,
        outcome.action,
        outcome.rule_version,
        outcome.reason,
        outcome.shadow_mode,
    )

    # --- Branch on the policy action --------------------------------------------
    if outcome.action == "auto_close":
        logger.info("pipeline: alert %s auto_closed (%s)", alert_id, outcome.reason)
        return

    if outcome.action == "auto_escalate":
        # Only reachable with jev_failed=False (evaluate() forces "queued" whenever
        # jev_failed=True), so `decision` is guaranteed non-None here.
        summary = _build_notification_summary(state)
        for notify_action in outcome.notify_actions:
            if notify_action == "notify_slack":
                result = send_slack_notification(str(alert_id), summary, decision.severity, decision.triage_verdict)
                logger.info("pipeline: slack notify for alert %s: %s", alert_id, result)
            elif notify_action == "page_pagerduty":
                result = page_pagerduty(
                    str(alert_id), summary, decision.severity, jev_verdict=decision.triage_verdict
                )
                logger.info("pipeline: pagerduty page for alert %s: %s", alert_id, result)
            else:
                logger.warning(
                    "pipeline: unknown notify_action %r for alert %s; skipping", notify_action, alert_id
                )
        return

    # outcome.action == "queued": both the normal default path AND the
    # Jev-failure fail-safe path land here (docs/architecture.md §2: "everything
    # else is escalated to the Tier-2 model").
    try:
        # Resolved once here (in addition to generate_brief_for_alert's own
        # internal resolution) purely to know which provider key/model name to
        # label the briefs/costs rows with -- worker.py's Brief doesn't carry that
        # itself. Both reads use the same override=None/pool resolution order
        # (providers.py's resolve_provider), so they agree in practice; a settings
        # change landing in the narrow gap between the two calls is a negligible,
        # documented risk for this MVP, not a correctness guarantee this code makes.
        provider = await resolve_provider(None, pool=pool)
        brief = await generate_brief_for_alert(pool, alert_row)
    except BudgetExceededError as exc:
        # docs/architecture.md §6: log a `budget_exceeded` event, skip generation,
        # never crash. No new table for this -- a structured log line is the spec.
        logger.error("budget_exceeded: alert_id=%s reason=%s", alert_id, exc)
        return
    except InvalidCitationError as exc:
        # worker.py already retried once internally per its own contract.
        logger.error(
            "pipeline: brief for alert %s still cited invalid log_line_id(s) after retry: %s",
            alert_id,
            exc.invalid_ids,
        )
        return

    await pool.execute(
        """
        INSERT INTO briefs (
            alert_id, provider_model, summary, attack_chain, mitre_techniques,
            recommended_actions, open_questions, cited_log_ids, tokens_in, tokens_out, cost_usd
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        """,
        alert_uuid,
        provider.provider_key,
        brief.summary,
        brief.attack_chain,
        brief.mitre_techniques,
        brief.recommended_actions,
        brief.open_questions,
        brief.cited_log_ids,
        brief.tokens_in,
        brief.tokens_out,
        brief.cost_usd,
    )
    await pool.execute(
        """
        INSERT INTO costs (alert_id, call_type, provider, model, tokens_in, tokens_out, cost_usd)
        VALUES ($1, 'tier2', 'openai', $2, $3, $4, $5)
        """,
        alert_uuid,
        provider.model,
        brief.tokens_in,
        brief.tokens_out,
        brief.cost_usd,
    )
    logger.info("pipeline: brief generated for alert %s (provider=%s)", alert_id, provider.provider_key)


async def run_pipeline(pool: asyncpg.Pool, alert_id: str) -> None:
    """Run the full live pipeline for one alert: normalize -> Jev -> policy ->
    notify/brief. Never raises -- a bug processing one alert must never crash the
    RQ worker process (docs/architecture.md §12); any unexpected error is logged
    with the alert id (visibly, via logger.exception) rather than swallowed.
    """
    try:
        await _run_pipeline_inner(pool, alert_id)
    except Exception:
        logger.exception("pipeline: unhandled error processing alert %s", alert_id)
