"""Shared utilities for the eval/ baseline and benchmark scripts.

This module is intentionally baseline-agnostic: `eval/baseline_majority.py`,
`eval/baseline_gbm.py`, and the later `eval/benchmark.py` (Jev tier, written
separately) all import from here rather than duplicating JSONL loading,
feature extraction, scoring, or result-writing logic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterator

from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# Fixed label order so every JSON report (and any confusion matrix built on
# top of it) is consistently ordered across scripts and runs.
LABELS = ["true_positive", "benign_positive", "false_positive"]

# The 8 fields under normalized.derived in the state object (see
# docs/architecture.md §4). Kept explicit so callers know exactly what
# `extract_derived_features` returns, and in what shape.
_BOOL_DERIVED_FIELDS = ("successful_auth_after_failures", "off_hours")
_CATEGORICAL_DERIVED_FIELDS = ("src_ip_reputation", "host_criticality")
_NUMERIC_DERIVED_FIELDS = (
    "failed_auth_10m",
    "src_ip_first_seen_days",
    "rule_historical_fp_rate",
    "similar_alerts_24h",
)


def load_jsonl(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield parsed JSON objects from a JSONL file, one per line.

    Streams line-by-line rather than loading the whole file, since the
    train split is ~440MB. Malformed lines are skipped with a warning to
    stderr rather than crashing the whole run.
    """
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                print(
                    f"warning: skipping malformed JSON at {path}:{line_no}: {e}",
                    file=sys.stderr,
                )


def extract_derived_features(record: dict[str, Any]) -> dict[str, Any]:
    """Pull `normalized.derived` out of a record and flatten it.

    - `successful_auth_after_failures` and `off_hours` are cast to int(bool).
    - `src_ip_reputation` and `host_criticality` are left as categorical
      strings (callers that need numeric arrays, e.g. the GBM script, encode
      them separately).
    - The remaining fields are passed through numerically as-is.

    Missing fields default to 0 (numeric/bool) or "unknown" (categorical) so
    a record with a sparse `derived` block doesn't blow up downstream.
    """
    derived = record.get("normalized", {}).get("derived", {}) or {}

    out: dict[str, Any] = {}
    for field in _BOOL_DERIVED_FIELDS:
        out[field] = int(bool(derived.get(field, False)))
    for field in _CATEGORICAL_DERIVED_FIELDS:
        out[field] = derived.get(field, "unknown")
    for field in _NUMERIC_DERIVED_FIELDS:
        value = derived.get(field, 0)
        out[field] = value if value is not None else 0
    return out


def macro_f1_and_report(
    y_true: list[str], y_pred: list[str], labels: list[str]
) -> dict[str, Any]:
    """Score predictions against ground truth, macro-F1 plus a per-class breakdown."""
    accuracy = accuracy_score(y_true, y_pred)
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average=None, zero_division=0
    )
    macro_f1 = float(f1.mean())

    per_class = {}
    for i, label in enumerate(labels):
        per_class[label] = {
            "precision": float(precision[i]),
            "recall": float(recall[i]),
            "f1": float(f1[i]),
            "support": int(support[i]),
        }

    return {
        "macro_f1": macro_f1,
        "accuracy": float(accuracy),
        "per_class": per_class,
    }


def write_results(path: str | Path, results: dict[str, Any]) -> Path:
    """Write `results` as indented JSON under eval/results/, creating the dir if needed.

    `path` may be a bare filename (e.g. "baseline_majority.json") or a full
    path; either way the file lands under eval/results/.
    """
    path = Path(path)
    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    out_path = results_dir / path.name
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    return out_path
