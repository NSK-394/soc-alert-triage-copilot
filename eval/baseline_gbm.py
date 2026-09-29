#!/usr/bin/env python
"""Gradient-boosted tree baseline for the GUIDE alert-triage benchmark.

Trains sklearn's HistGradientBoostingClassifier on exactly the 8 `derived`
features from the state object in docs/architecture.md §4 -- the same
features Jev sees. That's the point of this baseline: it's the ceiling a
cheap, fast, feature-only model can reach, to compare against Jev's
full-context typed answers later in eval/benchmark.py.

Categorical features (`src_ip_reputation`, `host_criticality`) are handled
via HistGradientBoostingClassifier's native `categorical_features` support
rather than manual one-hot encoding. Because that parameter still requires
numeric (float) columns under the hood -- see the sklearn docstring for
`categorical_features`, "All categorical values are converted to floating
point numbers" -- the two categorical columns are first ordinal-encoded
with `OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)`
fit on train only, and then marked categorical via the boolean
`categorical_features` mask. HistGradientBoostingClassifier treats negative
values on categorical columns as missing, so an unseen category at
val/test time degrades gracefully (treated as missing-category) instead of
crashing -- this is what "avoids unseen-category issues" means here, since
raw-string categoricals aren't accepted unless X is a pandas/polars
DataFrame with dtype="category" (`categorical_features="from_dtype"`),
which would add a pandas dependency this project is otherwise avoiding.

Trade-off / judgment call: the full train split is ~195k rows but only 8
features, so HistGradientBoostingClassifier trains in well under a minute
on it -- no downsampling was needed in practice. `--max-train-rows` is
still exposed as an escape hatch (randomly subsamples train, fixed seed)
for slower machines; if used, the run is clearly labeled as subsampled in
both stdout and the written JSON.

Usage:
    python baseline_gbm.py
    python baseline_gbm.py --data-dir data/datasets/guide
    python baseline_gbm.py --max-train-rows 100000
"""

from __future__ import annotations

import argparse
import random
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.preprocessing import OrdinalEncoder

from common import LABELS, extract_derived_features, load_jsonl, macro_f1_and_report, write_results

# Fixed column order for the 8 derived features, matching the order they
# appear in the state-object spec (docs/architecture.md §4).
FEATURE_ORDER = [
    "failed_auth_10m",
    "successful_auth_after_failures",
    "off_hours",
    "src_ip_first_seen_days",
    "src_ip_reputation",
    "host_criticality",
    "rule_historical_fp_rate",
    "similar_alerts_24h",
]
CATEGORICAL_FEATURES = {"src_ip_reputation", "host_criticality"}
CATEGORICAL_MASK = [name in CATEGORICAL_FEATURES for name in FEATURE_ORDER]


def load_split(data_dir: Path, split_name: str, max_rows: int | None = None) -> tuple[list[dict], list[str]]:
    """Stream a split, extracting (feature_dict, label) pairs, excluding unlabeled rows.

    If max_rows is set, reservoir-samples down to that many rows (fixed
    seed) rather than just taking the first N, so the subsample isn't
    biased toward whatever ordering the file happens to be in.
    """
    features: list[dict] = []
    labels: list[str] = []
    rng = random.Random(42)
    seen = 0
    for record in load_jsonl(data_dir / f"guide_{split_name}.jsonl"):
        label = record.get("ground_truth_label")
        if label is None:
            continue
        feats = extract_derived_features(record)
        seen += 1
        if max_rows is None or len(features) < max_rows:
            features.append(feats)
            labels.append(label)
        else:
            # reservoir sampling
            j = rng.randint(0, seen - 1)
            if j < max_rows:
                features[j] = feats
                labels[j] = label
    return features, labels


def to_matrix(features: list[dict], encoder: OrdinalEncoder, fit: bool) -> np.ndarray:
    """Convert a list of feature dicts into the fixed-column float matrix HGBC expects."""
    numeric_cols = [name for name in FEATURE_ORDER if name not in CATEGORICAL_FEATURES]
    cat_raw = np.array(
        [[feats[name] for name in FEATURE_ORDER if name in CATEGORICAL_FEATURES] for feats in features],
        dtype=object,
    )
    if fit:
        cat_encoded = encoder.fit_transform(cat_raw)
    else:
        cat_encoded = encoder.transform(cat_raw)

    numeric = np.array([[float(feats[name]) for name in numeric_cols] for feats in features], dtype=float)

    # Reassemble columns in FEATURE_ORDER.
    n_rows = len(features)
    out = np.empty((n_rows, len(FEATURE_ORDER)), dtype=float)
    num_i = 0
    cat_i = 0
    for col_i, name in enumerate(FEATURE_ORDER):
        if name in CATEGORICAL_FEATURES:
            out[:, col_i] = cat_encoded[:, cat_i]
            cat_i += 1
        else:
            out[:, col_i] = numeric[:, num_i]
            num_i += 1
    return out


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
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--data-dir",
        default="data/datasets/guide",
        help="directory containing guide_train/val/test.jsonl (default: data/datasets/guide)",
    )
    parser.add_argument(
        "--max-train-rows",
        type=int,
        default=None,
        help="randomly subsample train to at most this many rows (default: use full train split)",
    )
    args = parser.parse_args()
    data_dir = Path(args.data_dir)

    t0 = time.time()
    print("loading train split...")
    train_features, train_labels = load_split(data_dir, "train", args.max_train_rows)
    n_train = len(train_features)
    subsampled = args.max_train_rows is not None
    print(f"  {n_train} labeled rows" + (f" (subsampled from full train, seed=42)" if subsampled else ""))

    encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
    X_train = to_matrix(train_features, encoder, fit=True)
    y_train = np.array(train_labels)

    print("training HistGradientBoostingClassifier...")
    t_fit0 = time.time()
    clf = HistGradientBoostingClassifier(
        categorical_features=CATEGORICAL_MASK,
        random_state=42,
    )
    clf.fit(X_train, y_train)
    fit_elapsed = time.time() - t_fit0
    print(f"  fit took {fit_elapsed:.1f}s")

    results: dict = {
        "n_train": n_train,
        "train_subsampled": subsampled,
        "max_train_rows": args.max_train_rows,
        "fit_seconds": fit_elapsed,
        "features": FEATURE_ORDER,
    }

    for split_name in ("val", "test"):
        print(f"\nloading {split_name} split...")
        features, labels = load_split(data_dir, split_name)
        X = to_matrix(features, encoder, fit=False)
        y_true = labels
        y_pred = clf.predict(X).tolist()
        report = macro_f1_and_report(y_true, y_pred, LABELS)
        print_summary(split_name, report)
        results[split_name] = report

    # Permutation importance is O(n_repeats * n_features) predict calls, so
    # run it on a fixed-size, seeded subsample of val to keep it cheap.
    try:
        print("\ncomputing permutation importance on a val subsample...")
        val_features, val_labels = load_split(data_dir, "val", max_rows=5000)
        X_val_sample = to_matrix(val_features, encoder, fit=False)
        y_val_sample = np.array(val_labels)
        perm = permutation_importance(
            clf, X_val_sample, y_val_sample, n_repeats=5, random_state=42, scoring="f1_macro"
        )
        results["permutation_importance"] = {
            name: {"mean": float(perm.importances_mean[i]), "std": float(perm.importances_std[i])}
            for i, name in enumerate(FEATURE_ORDER)
        }
        print("  done")
    except Exception as e:  # pragma: no cover - nice-to-have, must not fail the run
        print(f"  skipped permutation importance ({e})")

    out_path = write_results("baseline_gbm.json", results)
    elapsed = time.time() - t0
    print(f"\nwrote {out_path} ({elapsed:.1f}s total)")


if __name__ == "__main__":
    main()
