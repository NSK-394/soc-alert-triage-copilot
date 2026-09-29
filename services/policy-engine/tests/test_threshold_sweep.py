"""Smoke tests for services/policy-engine/threshold_sweep.py.

Not explicitly required by the task list, but threshold_sweep.sweep_auto_close_fnr is
imported directly by eval/benchmark.py in a later phase, so a couple of correctness checks
here catch regressions before that integration happens.
"""

from evaluator import load_policy
from threshold_sweep import sweep_auto_close_fnr

import os

POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy", "v1.yaml")


def make_record(verdict, confidence, severity, ground_truth, host="normal", rule_id="r1"):
    return {
        "jev_verdict": verdict,
        "jev_confidence": confidence,
        "jev_severity": severity,
        "host_criticality": host,
        "rule_id": rule_id,
        "ground_truth_label": ground_truth,
    }


def test_sweep_reports_fnr_among_auto_closed_records_only():
    policy = load_policy(POLICY_PATH)
    records = [
        # Would auto_close at threshold 0.80 (confidence 0.85 >= 0.80), ground truth true_positive -> FN
        make_record("false_positive", 0.85, "informational", "true_positive"),
        # Would auto_close at threshold 0.80, ground truth false_positive -> correct
        make_record("false_positive", 0.88, "informational", "false_positive"),
        # Never eligible for auto_close (severity too high) -- excluded from denominator entirely
        make_record("false_positive", 0.99, "high", "true_positive"),
    ]

    results = sweep_auto_close_fnr(records, policy, confidence_thresholds=[0.80, 0.90])

    by_threshold = {r["confidence_threshold"]: r for r in results}

    # At 0.80: both eligible-severity records (0.85, 0.88) clear the bar and auto_close.
    r80 = by_threshold[0.80]
    assert r80["auto_close_count"] == 2
    assert r80["auto_close_false_negatives"] == 1
    assert r80["auto_close_fnr"] == 0.5

    # At 0.90: neither 0.85 nor 0.88 clears the bar -> nothing auto_closed -> fnr is None.
    r90 = by_threshold[0.90]
    assert r90["auto_close_count"] == 0
    assert r90["auto_close_false_negatives"] == 0
    assert r90["auto_close_fnr"] is None


def test_sweep_does_not_mutate_input_policy():
    policy = load_policy(POLICY_PATH)
    original_confidence_gte = policy["auto_close"]["when"]["confidence_gte"]

    sweep_auto_close_fnr(
        [make_record("false_positive", 0.99, "informational", "false_positive")],
        policy,
        confidence_thresholds=[0.10, 0.50, 0.99],
    )

    assert policy["auto_close"]["when"]["confidence_gte"] == original_confidence_gte
