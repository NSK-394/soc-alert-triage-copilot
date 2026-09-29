"""Unit tests for services/policy-engine/evaluator.py.

Uses a small in-memory policy dict mirroring policy/v1.yaml's shape rather than loading
the real file, so tests stay independent of the shipped YAML's exact threshold values
(which a later benchmark phase may retune). A separate test exercises load_policy() against
the real v1.yaml on disk to make sure the file itself parses and round-trips correctly.
"""

import os

import pytest

from evaluator import PolicyOutcome, SEVERITY_ORDER, evaluate, load_policy

POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy", "v1.yaml")


def base_policy(never_auto_close_list=None):
    return {
        "version": "v1-test",
        "auto_close": {
            "when": {
                "verdict_in": ["false_positive", "benign_positive"],
                "confidence_gte": 0.90,
                "severity_lt": "low",
            },
            "unless": {
                "host_criticality": "crown_jewel",
                "rule_id_in_never_auto_close": True,
            },
        },
        "auto_escalate": {
            "when": {
                "verdict_in": ["true_positive"],
                "confidence_gte": 0.85,
                "severity_gte": "high",
            },
            "action": ["page_pagerduty", "notify_slack"],
        },
        "default": "queued",
        "never_auto_close_list": never_auto_close_list or [],
    }


def call(policy, **overrides):
    args = dict(
        jev_verdict="false_positive",
        jev_confidence=0.95,
        jev_severity="informational",
        host_criticality="normal",
        rule_id="rule-1",
        jev_failed=False,
        shadow_mode=False,
    )
    args.update(overrides)
    return evaluate(policy, **args)


def test_auto_close_fires_on_clear_false_positive():
    outcome = call(base_policy(), jev_verdict="false_positive", jev_confidence=0.95, jev_severity="informational")
    assert outcome.action == "auto_close"
    assert outcome.rule_version == "v1-test"
    assert outcome.notify_actions == []
    assert not outcome.shadow_mode
    assert "auto_close" in outcome.reason
    assert "false_positive" in outcome.reason


def test_auto_close_blocked_by_crown_jewel_host_even_when_thresholds_met():
    outcome = call(
        base_policy(),
        jev_verdict="false_positive",
        jev_confidence=0.99,
        jev_severity="informational",
        host_criticality="crown_jewel",
    )
    assert outcome.action == "queued"
    assert "crown_jewel" in outcome.reason


def test_auto_close_blocked_by_never_auto_close_list():
    policy = base_policy(never_auto_close_list=["ransomware-detector-7"])
    outcome = call(
        policy,
        jev_verdict="false_positive",
        jev_confidence=0.99,
        jev_severity="informational",
        host_criticality="normal",
        rule_id="ransomware-detector-7",
    )
    assert outcome.action == "queued"
    assert "never_auto_close_list" in outcome.reason
    assert "ransomware-detector-7" in outcome.reason


def test_never_auto_close_list_does_not_block_unrelated_rule_ids():
    policy = base_policy(never_auto_close_list=["ransomware-detector-7"])
    outcome = call(
        policy,
        jev_verdict="false_positive",
        jev_confidence=0.99,
        jev_severity="informational",
        host_criticality="normal",
        rule_id="some-other-rule",
    )
    assert outcome.action == "auto_close"


def test_auto_escalate_fires_on_clear_true_positive_with_correct_notify_actions():
    outcome = call(
        base_policy(),
        jev_verdict="true_positive",
        jev_confidence=0.90,
        jev_severity="critical",
    )
    assert outcome.action == "auto_escalate"
    assert outcome.notify_actions == ["page_pagerduty", "notify_slack"]
    assert "auto_escalate" in outcome.reason
    assert "true_positive" in outcome.reason


@pytest.mark.parametrize(
    "kwargs",
    [
        # verdict not in either rule's verdict_in
        dict(jev_verdict="other", jev_confidence=0.99, jev_severity="critical"),
        # true_positive but confidence too low for auto_escalate, and verdict not eligible for auto_close
        dict(jev_verdict="true_positive", jev_confidence=0.50, jev_severity="critical"),
        # false_positive but confidence too low for auto_close
        dict(jev_verdict="false_positive", jev_confidence=0.50, jev_severity="informational"),
        # false_positive, high confidence, but severity too high for auto_close (not low<low)
        dict(jev_verdict="false_positive", jev_confidence=0.99, jev_severity="high"),
    ],
)
def test_everything_else_falls_to_queued_default(kwargs):
    outcome = call(base_policy(), host_criticality="normal", rule_id="rule-1", **kwargs)
    assert outcome.action == "queued"
    assert outcome.notify_actions == []


def test_jev_failed_always_returns_queued_overriding_would_be_auto_close():
    # These inputs would otherwise clearly auto_close.
    outcome = call(
        base_policy(),
        jev_verdict="false_positive",
        jev_confidence=0.99,
        jev_severity="informational",
        host_criticality="normal",
        jev_failed=True,
    )
    assert outcome.action == "queued"
    assert "jev_failed" in outcome.reason.lower() or "unavailable" in outcome.reason.lower()


def test_jev_failed_always_returns_queued_overriding_would_be_auto_escalate():
    # These inputs would otherwise clearly auto_escalate.
    outcome = call(
        base_policy(),
        jev_verdict="true_positive",
        jev_confidence=0.99,
        jev_severity="critical",
        host_criticality="normal",
        jev_failed=True,
    )
    assert outcome.action == "queued"
    assert outcome.notify_actions == []
    assert "jev_failed" in outcome.reason.lower() or "unavailable" in outcome.reason.lower()


@pytest.mark.parametrize("shadow_mode", [True, False])
def test_shadow_mode_flag_passes_through_correctly(shadow_mode):
    outcome = call(
        base_policy(),
        jev_verdict="false_positive",
        jev_confidence=0.95,
        jev_severity="informational",
        shadow_mode=shadow_mode,
    )
    assert outcome.shadow_mode is shadow_mode
    # shadow_mode must not change which action is computed
    assert outcome.action == "auto_close"


def test_shadow_mode_does_not_change_computed_action_for_jev_failed():
    outcome = call(
        base_policy(),
        jev_verdict="false_positive",
        jev_confidence=0.95,
        jev_severity="informational",
        jev_failed=True,
        shadow_mode=True,
    )
    assert outcome.action == "queued"
    assert outcome.shadow_mode is True


# --- ordinal severity comparison edge cases -------------------------------------------------


def test_severity_order_constant_is_the_documented_ordinal():
    assert SEVERITY_ORDER == ("informational", "low", "high", "critical")


def test_severity_lt_boundary_informational_is_strictly_less_than_low():
    # informational < low -> auto_close eligible
    outcome = call(base_policy(), jev_severity="informational", jev_verdict="false_positive", jev_confidence=0.95)
    assert outcome.action == "auto_close"


def test_severity_lt_boundary_low_itself_is_not_less_than_low():
    # low is NOT < low -> auto_close severity condition fails -> falls to queued
    outcome = call(base_policy(), jev_severity="low", jev_verdict="false_positive", jev_confidence=0.95)
    assert outcome.action == "queued"


def test_severity_gte_boundary_high_itself_satisfies_gte_high():
    outcome = call(
        base_policy(), jev_verdict="true_positive", jev_confidence=0.90, jev_severity="high"
    )
    assert outcome.action == "auto_escalate"


def test_severity_gte_boundary_low_does_not_satisfy_gte_high():
    outcome = call(
        base_policy(), jev_verdict="true_positive", jev_confidence=0.90, jev_severity="low"
    )
    assert outcome.action == "queued"


def test_severity_gte_critical_satisfies_gte_high():
    outcome = call(
        base_policy(), jev_verdict="true_positive", jev_confidence=0.90, jev_severity="critical"
    )
    assert outcome.action == "auto_escalate"


def test_unknown_severity_raises():
    with pytest.raises(ValueError):
        call(base_policy(), jev_severity="not_a_real_severity")


# --- PolicyOutcome shape --------------------------------------------------------------------


def test_policy_outcome_is_the_documented_shape():
    outcome = call(base_policy())
    assert isinstance(outcome, PolicyOutcome)
    assert hasattr(outcome, "action")
    assert hasattr(outcome, "rule_version")
    assert hasattr(outcome, "reason")
    assert hasattr(outcome, "shadow_mode")
    assert hasattr(outcome, "notify_actions")


# --- real v1.yaml on disk --------------------------------------------------------------------


def test_load_real_policy_v1_yaml_and_evaluate_against_it():
    policy = load_policy(POLICY_PATH)
    assert policy["version"] == "v1"
    assert policy["never_auto_close_list"] == []
    assert policy["default"] == "queued"

    # Defaults from the shipped file: 0.90 confidence, severity_lt low.
    outcome = evaluate(
        policy,
        jev_verdict="false_positive",
        jev_confidence=0.95,
        jev_severity="informational",
        host_criticality="normal",
        rule_id="rule-1",
    )
    assert outcome.action == "auto_close"
    assert outcome.rule_version == "v1"
