#!/usr/bin/env python
"""Jev-tier benchmark for the GUIDE alert-triage dataset (docs/architecture.md §5, §8, §10;
Phase B task 3, §12).

Runs the real Jev API (via `services/jev-client`) over a GUIDE split, scores it against the
same `eval/common.py` metrics the two baselines use, builds a calibration/reliability table
for `is_false_positive_prob`, sweeps the policy engine's `auto_close` confidence threshold via
`services/policy-engine/threshold_sweep.py`, and writes a combined report comparing Jev against
both baselines (loaded from their already-written `eval/results/*.json`, never re-run here).

*** Known real-world constraint (read before assuming a bug) ***
The real `TYPESAFE_API_KEY` in `.env` is waitlist-gated and returns 401 from the live Jev API.
Separately -- discovered while building this script, and worth flagging explicitly because it
is NOT the documented failure mode -- the GUIDE converter's `normalized.alert.rule_level` field
is `null` for every row in the shipped dataset, while `services/jev-client/question_catalog.py`'s
`JevStateObject.alert.rule_level` is a required `int`. That means `JevClient.score_alert(record
["normalized"])`, called exactly as this dataset produces it, fails pydantic validation *before*
any network call ever happens -- a `pydantic.ValidationError`, not the documented
`JevUnavailableError`. This script's preflight step is written to survive either failure mode
(or any other unexpected exception) without crashing and without fabricating numbers; whichever
one actually happens is reported verbatim. Fixing the root cause is out of scope here (it lives
in `data/converters/guide_to_state.py` and/or `services/jev-client`, both off-limits to this
task) -- this script only needs to not choke on it and to report it honestly.

Usage:
    python benchmark.py --split val --max-records 2000
    python benchmark.py --split test --max-records 0   # 0 = unlimited (all labeled rows)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "services" / "jev-client"))
sys.path.insert(0, str(REPO_ROOT / "services" / "policy-engine"))

from common import LABELS, load_jsonl, macro_f1_and_report, write_results  # noqa: E402
from client import JevClient, JevDecision, JevUnavailableError  # noqa: E402
from threshold_sweep import sweep_auto_close_fnr  # noqa: E402

DATA_DIR = REPO_ROOT / "data" / "datasets" / "guide"
RESULTS_DIR = REPO_ROOT / "eval" / "results"

# Transcribed from docs/architecture.md §8's policy/v1.yaml example. No policy/v1.yaml file
# exists in the repo yet (policy-engine's own CLI/YAML loading is a later phase, §12 Phase C),
# and threshold_sweep.sweep_auto_close_fnr() takes a policy *dict* directly, not a file path --
# so this benchmark constructs that dict inline rather than reaching into policy-engine's
# directory for a file that isn't there.
DEFAULT_POLICY: dict[str, Any] = {
    "version": "benchmark-v1",
    "auto_close": {
        "when": {
            "verdict_in": ["false_positive", "benign_positive"],
            # confidence_gte is overwritten per-candidate by sweep_auto_close_fnr(); the value
            # here is just a placeholder so the policy dict is well-formed on its own.
            "confidence_gte": 0.90,
            "severity_lt": "high",
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
    # No real never-auto-close rule_id list exists yet in this repo (that's a later,
    # security-review-driven list per §8's comment "ransomware, credential dumping, etc.") --
    # left empty so the `unless.rule_id_in_never_auto_close` guard is well-defined but inert.
    "never_auto_close_list": [],
}

DEFAULT_THRESHOLDS = [0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95]

# The "other" verdict is out-of-scheme for GUIDE's 3-class ground truth (docs/architecture.md
# §5: triage_verdict has 4 options, GUIDE only ever labels TP/BP/FP). Per this task's spec, an
# "other" prediction is scored as always-wrong against whichever the true label was. This falls
# out for free from sklearn's labels= restriction (verified empirically: an "other" prediction
# is never counted as a TP for any of the 3 labels, so it's correctly a false negative for its
# true class) -- see this module's `score_jev` for where that's relied on, and it is NOT a
# silent drop: "other" rows stay in y_true/y_pred, so per-class `support` totals are unaffected.


def load_split_records(split: str, max_records: int) -> list[dict[str, Any]]:
    """Load labeled records from guide_<split>.jsonl, capped at max_records (0 = unlimited)."""
    records: list[dict[str, Any]] = []
    for record in load_jsonl(DATA_DIR / f"guide_{split}.jsonl"):
        if record.get("ground_truth_label") is None:
            continue
        records.append(record)
        if max_records and len(records) >= max_records:
            break
    return records


def preflight(client: JevClient, record: dict[str, Any]) -> tuple[bool, JevDecision | None, str | None]:
    """Score exactly ONE record before committing to a full run.

    Returns (available, decision_if_available, error_message_if_not). Catches
    JevUnavailableError (the documented fail-safe contract) AND any other exception (e.g. the
    pydantic ValidationError described in this module's docstring, which is a data-contract
    mismatch, not the documented failure mode) -- either way, a failure here means "don't loop
    over thousands of records against a guaranteed-failing call."
    """
    try:
        decision = client.score_alert(record["normalized"])
        return True, decision, None
    except JevUnavailableError as e:
        return False, None, f"JevUnavailableError (documented fail-safe contract): {e}"
    except Exception as e:  # noqa: BLE001 - deliberately broad; see docstring
        return False, None, f"{type(e).__name__} (unexpected -- not the documented JevUnavailableError): {e}"


def run_full_scoring(
    client: JevClient,
    records: list[dict[str, Any]],
    seed_pair: tuple[dict[str, Any], JevDecision] | None,
) -> tuple[list[tuple[dict[str, Any], JevDecision]], int, int]:
    """Score every record, returning (successful (record, decision) pairs, n_failed,
    n_unexpected_errors). A per-record JevUnavailableError after a successful preflight does
    NOT abort the run -- it's recorded as a Jev failure and the loop continues (matches the
    fail-safe behavior the live pipeline also implements: never abort, never fabricate).
    """
    results: list[tuple[dict[str, Any], JevDecision]] = []
    n_failed = 0
    n_unexpected = 0

    start_index = 0
    if seed_pair is not None:
        results.append(seed_pair)
        start_index = 1  # records[0] was already scored during preflight

    total = len(records)
    t0 = time.time()
    for i in range(start_index, total):
        record = records[i]
        try:
            decision = client.score_alert(record["normalized"])
            results.append((record, decision))
        except JevUnavailableError as e:
            n_failed += 1
            print(f"  [{i + 1}/{total}] Jev failure (fail-safe, continuing): {e}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 - never let one bad record kill the whole run
            n_unexpected += 1
            print(f"  [{i + 1}/{total}] unexpected error (continuing): {type(e).__name__}: {e}", file=sys.stderr)

        if (i + 1) % 200 == 0 or (i + 1) == total:
            elapsed = time.time() - t0
            print(f"  scored {i + 1}/{total} ({elapsed:.1f}s elapsed)")

    return results, n_failed, n_unexpected


def score_jev(pairs: list[tuple[dict[str, Any], JevDecision]]) -> dict[str, Any]:
    """macro-F1/accuracy/per-class for the records Jev actually returned a decision for.

    "other" verdicts are NOT filtered out -- they stay in y_true/y_pred (see module docstring)
    so they count as wrong against whichever the true label was, and per-class support totals
    stay correct.
    """
    y_true = [record["ground_truth_label"] for record, _ in pairs]
    y_pred = [decision.triage_verdict for _, decision in pairs]
    report = macro_f1_and_report(y_true, y_pred, LABELS)

    other_count = sum(1 for v in y_pred if v == "other")
    other_breakdown: dict[str, int] = {}
    for true_label, pred in zip(y_true, y_pred):
        if pred == "other":
            other_breakdown[true_label] = other_breakdown.get(true_label, 0) + 1

    report["n_scored"] = len(pairs)
    report["other_verdict_count"] = other_count
    report["other_verdict_breakdown_by_true_label"] = other_breakdown
    report["other_verdict_scoring_note"] = (
        "'other' predictions are scored as always-wrong against the true label (never a TP for "
        "any of the 3 GUIDE classes) and are NOT dropped from the denominator -- per-class "
        "support totals include them."
    )
    return report


def build_calibration_bins(pairs: list[tuple[dict[str, Any], JevDecision]], n_bins: int = 10) -> list[dict[str, Any]]:
    """Reliability-diagram data for `is_false_positive_prob` (docs/architecture.md §10: "does
    90% confidence mean 90% correct?").

    Judgment call: `is_false_positive_prob` is Jev's own forecast of P(ground truth ==
    "false_positive") (question_catalog.py: "independent cross-check against triage_verdict").
    So for each bin of predicted probability, `actual_accuracy` is the empirical frequency that
    ground_truth_label really was "false_positive" among alerts whose is_false_positive_prob
    fell in that bin -- the standard reliability-diagram definition (predicted probability of an
    event vs. how often that event actually happened), not the unrelated 3-class triage_verdict
    accuracy.
    """
    bins: list[dict[str, Any]] = []
    edges = [i / n_bins for i in range(n_bins + 1)]
    for i in range(n_bins):
        lo, hi = edges[i], edges[i + 1]
        in_bin = [
            (decision.is_false_positive_prob, record["ground_truth_label"])
            for record, decision in pairs
            if (lo <= decision.is_false_positive_prob < hi) or (i == n_bins - 1 and decision.is_false_positive_prob == hi)
        ]
        count = len(in_bin)
        if count:
            predicted_avg = sum(p for p, _ in in_bin) / count
            actual_acc = sum(1 for _, true_label in in_bin if true_label == "false_positive") / count
        else:
            predicted_avg = None
            actual_acc = None
        bins.append(
            {
                "bin_range": [lo, hi],
                "predicted_confidence_avg": predicted_avg,
                "actual_accuracy": actual_acc,
                "count": count,
            }
        )
    return bins


def build_policy_records(pairs: list[tuple[dict[str, Any], JevDecision]]) -> list[dict[str, Any]]:
    """Adapter: (guide record, JevDecision) -> the record shape threshold_sweep.py's docstring
    documents (`jev_verdict`, `jev_confidence`, `jev_severity`, `host_criticality`, `rule_id`,
    `ground_truth_label`).

    Judgment call on `jev_confidence`: uses `confidence_margin` (top1-top2 margin computed on
    the `triage_verdict` distribution, per client.py -- NOT `is_false_positive_prob`, which is a
    separate cross-check question). The policy engine's `auto_close`/`auto_escalate` rules key
    off confidence in the *verdict itself* (docs/architecture.md §8's `confidence_gte`), and
    `confidence_margin` is exactly the "don't trust a single bundled confidence value" signal
    §5 defines for that verdict. Only records with a successful Jev decision are included --
    sweep_auto_close_fnr's evaluate() call always passes jev_failed=False, so a failed-Jev
    record has no meaningful way to enter this sweep (matches the live pipeline: a Jev failure
    always routes to `queued`, never `auto_close`, so it can never appear in an auto-close FNR
    count).
    """
    out = []
    for record, decision in pairs:
        out.append(
            {
                "jev_verdict": decision.triage_verdict,
                "jev_confidence": decision.confidence_margin,
                "jev_severity": decision.severity,
                "host_criticality": record["normalized"]["derived"].get("host_criticality", "unknown"),
                "rule_id": record["normalized"]["alert"]["rule_id"],
                "ground_truth_label": record["ground_truth_label"],
            }
        )
    return out


def recommend_threshold(sweep_table: list[dict[str, Any]]) -> dict[str, Any]:
    """Pick the threshold(s) that keep auto-close FNR at/near zero, per docs/architecture.md §8's
    explicit ask ("pick the point that keeps auto-close false-negatives near zero"). Prefers the
    LOWEST threshold with fnr == 0.0 and auto_close_count > 0 (maximizes auto-close volume
    without any known false negative in this sample); a threshold with auto_close_count == 0 is
    trivially "0 FNR" but auto-closes nothing, so it's excluded from the headline pick and
    called out separately.
    """
    zero_fnr_with_volume = [
        row for row in sweep_table if row["auto_close_fnr"] == 0.0 and row["auto_close_count"] > 0
    ]
    zero_volume = [row for row in sweep_table if row["auto_close_count"] == 0]
    if zero_fnr_with_volume:
        best = min(zero_fnr_with_volume, key=lambda r: r["confidence_threshold"])
        note = (
            f"threshold {best['confidence_threshold']} keeps auto_close_fnr at 0.0 while still "
            f"auto-closing {best['auto_close_count']} alerts in this sample -- the lowest such "
            f"threshold, i.e. the most auto-close volume with zero observed false negatives."
        )
        return {"recommended_threshold": best["confidence_threshold"], "note": note}

    non_zero_volume = [row for row in sweep_table if row["auto_close_count"] > 0]
    if non_zero_volume:
        best = min(non_zero_volume, key=lambda r: (r["auto_close_fnr"], r["confidence_threshold"]))
        note = (
            f"NO candidate threshold reached auto_close_fnr == 0.0 with nonzero auto-close "
            f"volume in this sample. Closest: threshold {best['confidence_threshold']} at "
            f"fnr={best['auto_close_fnr']:.4f} ({best['auto_close_false_negatives']}/"
            f"{best['auto_close_count']} auto-closed alerts were actually true positives)."
        )
        return {"recommended_threshold": best["confidence_threshold"], "note": note}

    note = "No candidate threshold ever triggered auto_close in this sample (auto_close_count == 0 for all)."
    if zero_volume:
        note += f" All {len(zero_volume)} thresholds tested had zero auto-close volume."
    return {"recommended_threshold": None, "note": note}


def load_baseline(name: str) -> dict[str, Any]:
    path = RESULTS_DIR / name
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def print_comparison_table(split: str, jev_report: dict[str, Any] | None, majority_split: dict, gbm_split: dict) -> None:
    print(f"\n=== Comparison table ({split}) ===")
    header = f"{'model':<18}{'macro-F1':>10}{'accuracy':>10}"
    print(header)
    print("-" * len(header))
    print(f"{'majority':<18}{majority_split['macro_f1']:>10.4f}{majority_split['accuracy']:>10.4f}")
    print(f"{'gbm':<18}{gbm_split['macro_f1']:>10.4f}{gbm_split['accuracy']:>10.4f}")
    if jev_report is not None:
        print(f"{'jev':<18}{jev_report['macro_f1']:>10.4f}{jev_report['accuracy']:>10.4f}  (n={jev_report['n_scored']})")
    else:
        print(f"{'jev':<18}{'n/a':>10}{'n/a':>10}  (Jev not available -- see report)")

    print(f"\n{'label':<20}{'model':<12}{'precision':>10}{'recall':>10}{'f1':>10}{'support':>10}")
    for label in LABELS:
        for name, split_report in (("majority", majority_split), ("gbm", gbm_split)):
            m = split_report["per_class"][label]
            print(f"{label:<20}{name:<12}{m['precision']:>10.4f}{m['recall']:>10.4f}{m['f1']:>10.4f}{m['support']:>10d}")
        if jev_report is not None:
            m = jev_report["per_class"][label]
            print(f"{label:<20}{'jev':<12}{m['precision']:>10.4f}{m['recall']:>10.4f}{m['f1']:>10.4f}{m['support']:>10d}")


def print_threshold_sweep(sweep_table: list[dict[str, Any]], recommendation: dict[str, Any]) -> None:
    print("\n=== Auto-close false-negative-rate sweep (the headline number for a security buyer) ===")
    print(f"{'threshold':>10}{'auto_close_count':>18}{'false_negatives':>17}{'fnr':>10}")
    for row in sweep_table:
        fnr_str = f"{row['auto_close_fnr']:.4f}" if row["auto_close_fnr"] is not None else "n/a"
        print(f"{row['confidence_threshold']:>10}{row['auto_close_count']:>18}{row['auto_close_false_negatives']:>17}{fnr_str:>10}")
    print(f"\n>>> RECOMMENDATION: {recommendation['note']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--split", choices=["val", "test"], default="val")
    parser.add_argument(
        "--max-records",
        type=int,
        default=2000,
        help="cap on labeled records to score (default 2000, matching the MVP's '>=2000 labeled "
        "alerts' bar; 0 = unlimited, i.e. score the whole split)",
    )
    parser.add_argument(
        "--thresholds",
        type=float,
        nargs="+",
        default=DEFAULT_THRESHOLDS,
        help=f"candidate auto_close confidence thresholds to sweep (default: {DEFAULT_THRESHOLDS})",
    )
    args = parser.parse_args()

    print(f"loading {args.split} split (max_records={args.max_records or 'unlimited'})...")
    records = load_split_records(args.split, args.max_records)
    print(f"  {len(records)} labeled records loaded")
    if not records:
        print("no labeled records found -- nothing to benchmark", file=sys.stderr)
        sys.exit(1)

    print("\nloading baseline results (not re-run)...")
    majority_results = load_baseline("baseline_majority.json")
    gbm_results = load_baseline("baseline_gbm.json")

    print("\nrunning Jev preflight (ONE record) before committing to a full run...")
    client = JevClient()
    jev_available, preflight_decision, preflight_error = preflight(client, records[0])

    jev_report: dict[str, Any] | None = None
    calibration_bins: list[dict[str, Any]] = []
    sweep_table: list[dict[str, Any]] = []
    recommendation: dict[str, Any] = {"recommended_threshold": None, "note": "not computed -- Jev unavailable"}
    n_failed = 0
    n_unexpected = 0
    n_scored = 0

    if not jev_available:
        print(f"\nJev API unreachable/unauthorized -- skipping live Jev benchmark, reporting baseline-only comparison.")
        print(f"  error: {preflight_error}")
    else:
        print("  preflight succeeded -- proceeding with full run")
        seed_pair = (records[0], preflight_decision) if preflight_decision is not None else None
        pairs, n_failed, n_unexpected = run_full_scoring(client, records, seed_pair)
        n_scored = len(pairs)
        print(f"\nscored {n_scored} records ({n_failed} Jev failures, {n_unexpected} unexpected errors)")

        if pairs:
            jev_report = score_jev(pairs)
            calibration_bins = build_calibration_bins(pairs)
            policy_records = build_policy_records(pairs)
            sweep_table = sweep_auto_close_fnr(policy_records, DEFAULT_POLICY, args.thresholds)
            recommendation = recommend_threshold(sweep_table)
        else:
            print("no successful Jev decisions after the full run -- reporting baseline-only comparison", file=sys.stderr)

    client.close()

    majority_split = majority_results[args.split]
    gbm_split = gbm_results[args.split]
    print_comparison_table(args.split, jev_report, majority_split, gbm_split)
    if sweep_table:
        print_threshold_sweep(sweep_table, recommendation)
    else:
        print("\n=== Auto-close false-negative-rate sweep ===\nnot run: no successful Jev decisions available.")

    report = {
        "split": args.split,
        "max_records_requested": args.max_records,
        "records_loaded": len(records),
        "jev": {
            "preflight_available": jev_available,
            "preflight_error": preflight_error,
            "n_scored": n_scored,
            "n_failed_after_preflight": n_failed,
            "n_unexpected_errors": n_unexpected,
            "metrics": jev_report,
        }
        if jev_available
        else {
            "preflight_available": False,
            "preflight_error": preflight_error,
            "note": "Jev API unreachable/unauthorized -- no live Jev numbers in this report. See preflight_error.",
        },
        "baseline_majority": {"majority_class": majority_results.get("majority_class"), **majority_split},
        "baseline_gbm": gbm_split,
        "calibration": {
            "signal": "is_false_positive_prob",
            "note": (
                "predicted_confidence_avg is the mean is_false_positive_prob in the bin; "
                "actual_accuracy is the empirical frequency that ground_truth_label == "
                "'false_positive' for records in that bin (standard reliability-diagram "
                "definition: predicted P(event) vs. observed frequency of that event). "
                "Empty when Jev is unavailable."
            ),
            "bins": calibration_bins,
        },
        "auto_close_threshold_sweep": {
            "policy": DEFAULT_POLICY,
            "confidence_signal_used": "confidence_margin (top1-top2 margin on triage_verdict's probability distribution)",
            "thresholds_tested": args.thresholds,
            "table": sweep_table,
            "recommendation": recommendation,
        },
    }

    out_path = write_results(f"benchmark_{args.split}.json", report)
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    main()
