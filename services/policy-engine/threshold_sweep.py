"""Reusable threshold-sweep helper for the auto_close confidence_gte threshold.

Not a CLI or a report generator — that's eval/benchmark.py's job in a later phase (built by a
different agent). This module exposes a single importable function that eval/benchmark.py
calls directly, passing in labeled records and getting back per-threshold metrics.

Per docs/architecture.md §8: "The metric that matters isn't accuracy — it's the
false-negative rate among alerts the policy would have auto-closed. Report that number
explicitly, even if it's not flattering." This module computes exactly that metric for a
list of candidate confidence_gte thresholds, so eval/benchmark.py can pick the threshold
that keeps auto-close false negatives near zero.
"""

from __future__ import annotations

import copy

from evaluator import evaluate

# Input record shape (each dict in `records`):
#   {
#       "jev_verdict": str,          # e.g. "false_positive", "benign_positive", "true_positive"
#       "jev_confidence": float,     # 0-1
#       "jev_severity": str,         # "informational" | "low" | "high" | "critical"
#       "host_criticality": str,     # e.g. "crown_jewel" or anything else
#       "rule_id": str,
#       "ground_truth_label": str,   # GUIDE's own label, e.g. "true_positive" | "false_positive" | ...
#   }
#
# Output shape (one dict per candidate threshold, same order as `confidence_thresholds`):
#   {
#       "confidence_threshold": float,
#       "auto_close_count": int,            # how many records this threshold would auto_close
#       "auto_close_false_negatives": int,  # of those, how many have ground_truth_label == "true_positive"
#       "auto_close_fnr": float | None,     # false_negatives / auto_close_count; None if auto_close_count == 0
#   }


def sweep_auto_close_fnr(
    records: list[dict],
    policy: dict,
    confidence_thresholds: list[float],
) -> list[dict]:
    """For each candidate auto_close confidence_gte threshold, report the false-negative
    rate among alerts that threshold would have auto-closed.

    A record counts as a false negative if the policy (with that candidate threshold) would
    auto_close it AND its ground_truth_label is "true_positive" — i.e. the policy would have
    silently closed an alert that was actually a real attack. This is evaluated in shadow
    mode conceptually: no alert is actually acted on here, this only counts what *would*
    happen under each threshold.

    The policy dict passed in is not mutated; a deep copy is patched per-threshold so
    concurrent callers (or repeated calls) never see cross-contamination.
    """
    results: list[dict] = []

    for threshold in confidence_thresholds:
        candidate_policy = copy.deepcopy(policy)
        candidate_policy.setdefault("auto_close", {}).setdefault("when", {})[
            "confidence_gte"
        ] = threshold

        auto_close_count = 0
        false_negatives = 0

        for record in records:
            outcome = evaluate(
                candidate_policy,
                jev_verdict=record["jev_verdict"],
                jev_confidence=record["jev_confidence"],
                jev_severity=record["jev_severity"],
                host_criticality=record["host_criticality"],
                rule_id=record["rule_id"],
                jev_failed=False,
                shadow_mode=True,
            )
            if outcome.action == "auto_close":
                auto_close_count += 1
                if record["ground_truth_label"] == "true_positive":
                    false_negatives += 1

        fnr = (false_negatives / auto_close_count) if auto_close_count else None

        results.append(
            {
                "confidence_threshold": threshold,
                "auto_close_count": auto_close_count,
                "auto_close_false_negatives": false_negatives,
                "auto_close_fnr": fnr,
            }
        )

    return results
