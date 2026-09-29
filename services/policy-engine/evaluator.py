"""Policy engine: deterministic rules evaluator (docs/architecture.md §8, §12 Phase C task 1).

Reads a versioned YAML ruleset (policy/v1.yaml) and a Jev decision plus minimal alert
context, and decides exactly one of three actions matching the `policy_outcomes.action`
CHECK constraint in infra/migrations/001_init.sql: "auto_close", "auto_escalate", "queued".

This module is pure and deterministic: zero network calls, zero I/O beyond reading the
policy YAML file. It only decides — it never sends notifications (services/notifier's job)
and never writes to the database (a later integration-layer phase's job).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

import yaml

# Ordinal severity order (docs/architecture.md §5: "4 levels: informational -> low -> high ->
# critical"). Always compare severities by their position in this tuple, never by string
# comparison — "critical" < "high" would be true lexically but is wrong semantically.
SEVERITY_ORDER: tuple[str, ...] = ("informational", "low", "high", "critical")


def _severity_rank(severity: str) -> int:
    """Return the ordinal rank of a severity level, raising on an unknown value.

    Raising (rather than silently defaulting) is deliberate: an unrecognized severity string
    is a data-contract bug upstream (jev-client / feature-builder), and silently treating it
    as e.g. rank 0 could let a mislabeled critical alert slip through auto_close.
    """
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError as exc:
        raise ValueError(
            f"unknown severity {severity!r}; expected one of {SEVERITY_ORDER}"
        ) from exc


PolicyAction = Literal["auto_close", "auto_escalate", "queued"]


@dataclass(frozen=True)
class PolicyOutcome:
    """The decision returned by evaluate(). Maps directly onto the `policy_outcomes` table
    (alert_id and created_at are the integration layer's concern, not this module's).
    """

    action: PolicyAction
    rule_version: str
    reason: str
    shadow_mode: bool
    # Populated only when action == "auto_escalate" (the YAML's auto_escalate.action list,
    # e.g. ["page_pagerduty", "notify_slack"]). services/notifier is what actually sends
    # these; this module only decides.
    notify_actions: list[str] = field(default_factory=list)


def load_policy(path: str) -> dict:
    """Load and return a versioned policy YAML file as a plain dict. No validation beyond
    what yaml.safe_load itself performs — evaluate() is defensive about missing/malformed
    keys via .get() with sane defaults, so a minimal or partial policy dict still behaves
    predictably (falls through to "queued").
    """
    with open(path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    if not isinstance(policy, dict):
        raise ValueError(f"policy file {path!r} did not parse to a mapping")
    return policy


def _verdict_matches(verdict_in: list[str] | None, jev_verdict: str) -> bool:
    if not verdict_in:
        return False
    return jev_verdict in verdict_in


def _confidence_matches(confidence_gte: float | None, jev_confidence: float) -> bool:
    if confidence_gte is None:
        return False
    return jev_confidence >= confidence_gte


def evaluate(
    policy: dict,
    *,
    jev_verdict: str,
    jev_confidence: float,
    jev_severity: str,
    host_criticality: str,
    rule_id: str,
    jev_failed: bool = False,
    shadow_mode: bool = False,
) -> PolicyOutcome:
    """Decide the policy action for one alert.

    Fail-safe (spec §5/§8): if jev_failed=True — the caller's signal that Jev was
    unavailable, matching jev-client's documented JevUnavailableError contract — this always
    returns "queued" with an explanatory reason, regardless of every other argument. This
    check runs before anything else and short-circuits the rest of the function, so no
    combination of verdict/confidence/severity/host_criticality/rule_id can override it.

    shadow_mode is passed through untouched into the returned PolicyOutcome (it does not
    change which action is computed) — shadow mode is the caller's responsibility to not
    act on, per spec; this function's only job re: shadow_mode is to record what was asked
    for, since that value is what gets written to policy_outcomes.shadow_mode.
    """
    rule_version = policy.get("version", "unknown")

    # --- Fail-safe: Jev unavailable always wins, before any other rule is considered. ---
    if jev_failed:
        return PolicyOutcome(
            action="queued",
            rule_version=rule_version,
            reason="queued: jev_failed=True (Jev unavailable) — fail-safe, never auto-act on a Jev failure",
            shadow_mode=shadow_mode,
            notify_actions=[],
        )

    severity_rank = _severity_rank(jev_severity)

    # --- auto_close ---
    auto_close_cfg = policy.get("auto_close") or {}
    when = auto_close_cfg.get("when") or {}
    unless = auto_close_cfg.get("unless") or {}

    verdict_in = when.get("verdict_in")
    confidence_gte = when.get("confidence_gte")
    severity_lt_name = when.get("severity_lt")

    verdict_ok = _verdict_matches(verdict_in, jev_verdict)
    confidence_ok = _confidence_matches(confidence_gte, jev_confidence)
    severity_ok = (
        severity_lt_name is not None and severity_rank < _severity_rank(severity_lt_name)
    )

    if verdict_ok and confidence_ok and severity_ok:
        # Check the "unless" guards. Either one blocks auto_close and falls through to the
        # default (queued) rather than auto_escalate — a blocked auto_close is not evidence
        # of a true positive, so escalation is not implied.
        blocked_reason = None

        required_host_criticality = unless.get("host_criticality")
        if required_host_criticality is not None and host_criticality == required_host_criticality:
            blocked_reason = (
                f"blocked: host_criticality={host_criticality!r} matches "
                f"unless.host_criticality={required_host_criticality!r}"
            )

        if blocked_reason is None and unless.get("rule_id_in_never_auto_close"):
            never_auto_close_list = policy.get("never_auto_close_list") or []
            if rule_id in never_auto_close_list:
                blocked_reason = f"blocked: rule_id={rule_id!r} is in never_auto_close_list"

        if blocked_reason is None:
            reason = (
                f"auto_close: verdict={jev_verdict} confidence={jev_confidence:.2f}"
                f">={confidence_gte:.2f} severity={jev_severity}<{severity_lt_name}"
            )
            return PolicyOutcome(
                action="auto_close",
                rule_version=rule_version,
                reason=reason,
                shadow_mode=shadow_mode,
                notify_actions=[],
            )
        else:
            reason = (
                f"auto_close criteria met (verdict={jev_verdict} "
                f"confidence={jev_confidence:.2f}>={confidence_gte:.2f} "
                f"severity={jev_severity}<{severity_lt_name}) but {blocked_reason}; "
                f"falling through to default"
            )
            # Continue evaluation (auto_escalate, then default) — don't return yet, but
            # remember why auto_close didn't fire in case nothing else fires either.
            auto_close_blocked_reason = reason
    else:
        auto_close_blocked_reason = None

    # --- auto_escalate ---
    auto_escalate_cfg = policy.get("auto_escalate") or {}
    ae_when = auto_escalate_cfg.get("when") or {}

    ae_verdict_in = ae_when.get("verdict_in")
    ae_confidence_gte = ae_when.get("confidence_gte")
    ae_severity_gte_name = ae_when.get("severity_gte")

    ae_verdict_ok = _verdict_matches(ae_verdict_in, jev_verdict)
    ae_confidence_ok = _confidence_matches(ae_confidence_gte, jev_confidence)
    ae_severity_ok = (
        ae_severity_gte_name is not None
        and severity_rank >= _severity_rank(ae_severity_gte_name)
    )

    if ae_verdict_ok and ae_confidence_ok and ae_severity_ok:
        notify_actions = list(auto_escalate_cfg.get("action") or [])
        reason = (
            f"auto_escalate: verdict={jev_verdict} confidence={jev_confidence:.2f}"
            f">={ae_confidence_gte:.2f} severity={jev_severity}>={ae_severity_gte_name}"
        )
        return PolicyOutcome(
            action="auto_escalate",
            rule_version=rule_version,
            reason=reason,
            shadow_mode=shadow_mode,
            notify_actions=notify_actions,
        )

    # --- default ---
    default_action = policy.get("default", "queued")
    if default_action != "queued":
        # The spec's only legal values are auto_close/auto_escalate/queued; guard against a
        # misconfigured policy YAML claiming a different default rather than silently
        # emitting an action the DB CHECK constraint would reject.
        raise ValueError(
            f"policy 'default' must be 'queued' to satisfy the policy_outcomes.action "
            f"CHECK constraint, got {default_action!r}"
        )

    if auto_close_blocked_reason is not None:
        reason = f"queued (default): {auto_close_blocked_reason}"
    else:
        reason = (
            f"queued (default): no rule matched "
            f"(verdict={jev_verdict} confidence={jev_confidence:.2f} severity={jev_severity})"
        )

    return PolicyOutcome(
        action="queued",
        rule_version=rule_version,
        reason=reason,
        shadow_mode=shadow_mode,
        notify_actions=[],
    )
