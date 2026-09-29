#!/usr/bin/env python
"""Majority-class baseline for the GUIDE alert-triage benchmark.

Computes the most common `ground_truth_label` on the train split, then
predicts that constant label for every row in val and test. This is the
floor every other approach (baseline_gbm.py, and eventually Jev) has to
clear — see docs/architecture.md §10.

Usage:
    python baseline_majority.py
    python baseline_majority.py --data-dir data/datasets/guide
"""

from __future__ import annotations

import argparse
import time
from collections import Counter
from pathlib import Path

from common import LABELS, load_jsonl, macro_f1_and_report, write_results


def most_common_label(data_dir: Path) -> tuple[str, int]:
    """Stream the train split and return (majority_label, rows_used).

    Rows with a null/missing ground_truth_label are excluded, per spec —
    the ~0.4-1% unlabeled rows are dropped from all training/scoring, not
    treated as a fourth class.
    """
    counts: Counter[str] = Counter()
    for record in load_jsonl(data_dir / "guide_train.jsonl"):
        label = record.get("ground_truth_label")
        if label is None:
            continue
        counts[label] += 1

    if not counts:
        raise RuntimeError("no labeled rows found in guide_train.jsonl")

    majority_label, _ = counts.most_common(1)[0]
    return majority_label, sum(counts.values())


def score_split(data_dir: Path, split_name: str, majority_label: str) -> dict:
    y_true: list[str] = []
    y_pred: list[str] = []
    for record in load_jsonl(data_dir / f"guide_{split_name}.jsonl"):
        label = record.get("ground_truth_label")
        if label is None:
            continue
        y_true.append(label)
        y_pred.append(majority_label)
    return macro_f1_and_report(y_true, y_pred, LABELS)


def print_summary(name: str, report: dict) -> None:
    print(f"\n{name} (n={sum(c['support'] for c in report['per_class'].values())})")
    print(f"  accuracy:  {report['accuracy']:.4f}")
    print(f"  macro-F1:  {report['macro_f1']:.4f}")
    print(f"  {'label':<20}{'precision':>10}{'recall':>10}{'f1':>10}{'support':>10}")
    for label, m in report["per_class"].items():
        print(
            f"  {label:<20}{m['precision']:>10.4f}{m['recall']:>10.4f}"
            f"{m['f1']:>10.4f}{m['support']:>10d}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir",
        default="data/datasets/guide",
        help="directory containing guide_train/val/test.jsonl (default: data/datasets/guide)",
    )
    args = parser.parse_args()
    data_dir = Path(args.data_dir)

    t0 = time.time()
    majority_label, n_train = most_common_label(data_dir)
    print(f"majority class on train (n={n_train}): {majority_label}")

    val_report = score_split(data_dir, "val", majority_label)
    test_report = score_split(data_dir, "test", majority_label)
    print_summary("val", val_report)
    print_summary("test", test_report)

    results = {
        "majority_class": majority_label,
        "val": val_report,
        "test": test_report,
    }
    out_path = write_results("baseline_majority.json", results)
    elapsed = time.time() - t0
    print(f"\nwrote {out_path} ({elapsed:.1f}s total)")


if __name__ == "__main__":
    main()
