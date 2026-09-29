"""Convert the Microsoft GUIDE security-incident dataset into Jev state-object `.jsonl`.

See docs/architecture.md §4 (Data model) and §7 (Ingestion and dataset pipeline) for the
authoritative design this converter implements, and Phase A task 4 in §12. Output is consumed
verbatim by `data/replay-harness` — see `data/replay-harness/README.md` for the exact `.jsonl`
contract this script must produce (one JSON object per line: `source`, `external_id`,
`incident_id`, `raw`, `normalized`, `ground_truth_label`).

CLI:

    python guide_to_state.py --input-dir data/datasets/guide --output-dir data/datasets/guide \\
        --max-rows-per-file 200000 --train-frac 0.70 --val-frac 0.15

`--max-rows-per-file 0` means unlimited (read the whole file).

Reads `GUIDE_Train.csv` and `GUIDE_Test.csv` from `--input-dir` line-by-line with `csv.DictReader`
(never loaded fully into memory) and writes `guide_train.jsonl`, `guide_val.jsonl`,
`guide_test.jsonl` into `--output-dir`.

Design decisions worth calling out
-----------------------------------

**We replace Microsoft's own Train/Test file boundary with our own split.** Both CSVs are read
into one combined pool of alerts, and that pool is re-split ourselves into train/val/test. We need
a held-out *validation* split for policy-threshold sweeping (see architecture.md §8) that
Microsoft's 2-file Train/Test layout doesn't give us, so we don't use their boundary at all —
every alert from both files is eligible for any of our three splits.

**`--max-rows-per-file` is a deliberate, documented trade-off, not a bug.** The combined dataset
is ~13.6M rows (9,516,837 in Train + 4,147,992 in Test), which is impractical to hold fully
aggregated in memory on a typical dev laptop. The default (200,000 rows per file, 400,000 total)
keeps memory bounded. Reprocessing the full dataset on a bigger machine is one flag away
(`--max-rows-per-file 0`). Row counts actually processed are always printed at the end of the run.

**Split is incident-level, not row- or alert-level, and is streaming-friendly.** Each CSV row is
one *entity-evidence* record (avg ~1.57 rows/alert), each alert belongs to exactly one incident
(avg ~2.16 alerts/incident, heavily skewed). A prior public benchmark on this exact dataset found
that splitting by row or by alert leaks label information across the split boundary (rows/alerts
from the same incident are highly correlated: same attacker behavior, same entities, near-identical
timestamps), which silently inflates offline accuracy. Every alert belonging to the same
`IncidentId` is forced into the same split by hashing `IncidentId` into a stable bucket
(`sha256(incident_id) % 100`) — deterministic and reproducible without a separate pre-pass to
enumerate all incidents first.

**`rule_historical_fp_rate` is computed from the train split only, then applied to all three
splits.** Computing it globally (train+val+test) would leak the val/test label distribution into a
feature those splits are then scored on. Detectors seen only in val/test (zero train occurrences)
get 0.0 — this reuses `services/feature-builder`'s own `rule_historical_fp_rate` function, which
already documents and clamps to that same default for missing lookup entries.

Fields that are genuinely not computable from GUIDE (left at conservative, documented defaults —
see the project README's eventual limitations section for the same list):

- `alert.rule_level`: GUIDE has no severity/level column analogous to Wazuh's `rule_level`. Left
  `null` rather than fabricated.
- `alert.rule_description`: GUIDE's `AlertTitle` is an anonymized numeric ID, not human-readable
  rule text. Prefixed `guide_alert_title_id:<id>` so it's obviously not real prose.
- `derived.failed_auth_10m` (0), `derived.successful_auth_after_failures` (false),
  `derived.src_ip_reputation` ("unknown"), `derived.host_criticality` ("unknown"): GUIDE has no raw
  auth-event log stream, no IP reputation feed, and no asset-criticality inventory, so these can't
  be computed from this dataset at all.
- `untrusted_evidence.raw_log_excerpt`: GUIDE has no raw log text field. Left as `""` rather than
  fabricating adversarial-looking "log" text — the prompt-injection test suite (a later phase) uses
  purpose-built synthetic fixtures instead, not GUIDE-derived data.

Fields that ARE genuinely computable and are computed for real (not defaulted):

- `derived.off_hours`: pure calendar arithmetic on the alert's real timestamp. Reuses
  `services/feature-builder/derived_fields.off_hours` directly (via a `sys.path` workaround — the
  hyphenated `services/feature-builder` directory name means it can't be imported with a normal
  dotted import; see that package's `__init__.py` for why it deliberately has no re-export).
- `derived.similar_alerts_24h`: a structural count (not a label, so it doesn't leak
  ground-truth into the feature) of *other* alerts sharing `(org_id, detector_id)` within ±24h of
  this alert's timestamp. Computed with `bisect` over each `(org_id, detector_id)` group's sorted
  timestamp list — O(n log n), not an O(n^2) all-pairs scan.
- `derived.rule_historical_fp_rate`: real, train-only empirical FP rate per detector (see above).
- `derived.src_ip_first_seen_days`: real, structural (not label-derived, computed across all
  splits — same leakage rationale as `similar_alerts_24h`), the number of days between this
  alert's timestamp and the earliest timestamp seen for the same `src_ip` (`IpAddress` column)
  anywhere in the loaded dataset. Alerts whose contributing rows never had a non-empty `IpAddress`
  (a real, if uncommon, case) get 0 — the same "just seen"/most-suspicious default
  `derived_fields.py` documents for a missing lookup entry, not fabricated data.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import json
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# --- import off_hours / rule_historical_fp_rate from services/feature-builder -----------------
# services/feature-builder is hyphenated, so `import services.feature-builder` is a syntax error
# and there's no re-export in its __init__.py (documented there as intentional, to avoid breaking
# pytest collection). The documented workaround is sys.path + a direct module import.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_FEATURE_BUILDER_DIR = _REPO_ROOT / "services" / "feature-builder"
if str(_FEATURE_BUILDER_DIR) not in sys.path:
    sys.path.insert(0, str(_FEATURE_BUILDER_DIR))
from derived_fields import off_hours, rule_historical_fp_rate  # noqa: E402

CSV_FILES = ["GUIDE_Train.csv", "GUIDE_Test.csv"]
PROGRESS_EVERY = 50_000

GRADE_MAP = {
    "TruePositive": "true_positive",
    "BenignPositive": "benign_positive",
    "FalsePositive": "false_positive",
}
# Tie-break priority when an alert's rows disagree on IncidentGrade (confirmed rare: 49/190,958
# alerts, 0.026%, in a 300k-row sample). On an exact vote tie, prefer the more severe label — a
# conservative default for a security tool, rather than silently picking iteration order.
GRADE_PRIORITY = ["TruePositive", "BenignPositive", "FalsePositive"]


# ---------------------------------------------------------------------------------------------
# Per-alert aggregate
# ---------------------------------------------------------------------------------------------


@dataclass
class AlertAgg:
    """Everything accumulated across a single AlertId's rows (Step 1 of the pipeline)."""

    alert_id: str
    incident_id: str
    org_id: str
    detector_id: str  # DetectorId, take-first (confirmed constant per alert)
    alert_title_id: str  # AlertTitle, take-first
    category: str  # Category, take-first (confirmed constant per alert)
    timestamp: datetime  # earliest Timestamp seen, tz-aware UTC

    mitre_techniques: set = field(default_factory=set)
    grade_votes: Counter = field(default_factory=Counter)

    first_ip: Optional[str] = None
    first_upn: Optional[str] = None
    first_account_name: Optional[str] = None
    first_account_sid: Optional[str] = None
    first_device_name: Optional[str] = None
    first_device_id: Optional[str] = None

    evidence_rows: list = field(default_factory=list)

    @property
    def user(self) -> Optional[str]:
        return self.first_upn or self.first_account_name or self.first_account_sid

    @property
    def host(self) -> Optional[str]:
        return self.first_device_name or self.first_device_id


def parse_timestamp(raw: str) -> datetime:
    """Parse GUIDE's ISO 8601 UTC timestamp (e.g. "2024-06-04T22:56:27.000Z") to tz-aware UTC.

    `datetime.fromisoformat` only started accepting a trailing "Z" in Python 3.11; this repo
    targets 3.11 (architecture.md §3) but is developed/run here on 3.10, so the "Z" is swapped for
    an explicit "+00:00" offset to stay compatible with both.
    """
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_iso_z(dt: datetime) -> str:
    """Render a tz-aware UTC datetime back in GUIDE's own "...000Z" millisecond style."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# ---------------------------------------------------------------------------------------------
# Step 1: parse + aggregate
# ---------------------------------------------------------------------------------------------


def _aggregate_row(alerts: dict[str, AlertAgg], row: dict) -> None:
    alert_id = row["AlertId"]
    ts = parse_timestamp(row["Timestamp"])

    agg = alerts.get(alert_id)
    if agg is None:
        agg = AlertAgg(
            alert_id=alert_id,
            incident_id=row["IncidentId"],
            org_id=row["OrgId"],
            detector_id=row["DetectorId"],
            alert_title_id=row["AlertTitle"],
            category=row["Category"],
            timestamp=ts,
        )
        alerts[alert_id] = agg
    elif ts < agg.timestamp:
        agg.timestamp = ts

    mitre_raw = row.get("MitreTechniques") or ""
    if mitre_raw:
        agg.mitre_techniques.update(t for t in mitre_raw.split(";") if t)

    grade = row.get("IncidentGrade") or ""
    if grade:
        agg.grade_votes[grade] += 1

    ip = row.get("IpAddress") or ""
    if ip and agg.first_ip is None:
        agg.first_ip = ip

    upn = row.get("AccountUpn") or ""
    if upn and agg.first_upn is None:
        agg.first_upn = upn
    acct_name = row.get("AccountName") or ""
    if acct_name and agg.first_account_name is None:
        agg.first_account_name = acct_name
    acct_sid = row.get("AccountSid") or ""
    if acct_sid and agg.first_account_sid is None:
        agg.first_account_sid = acct_sid

    device_name = row.get("DeviceName") or ""
    if device_name and agg.first_device_name is None:
        agg.first_device_name = device_name
    device_id = row.get("DeviceId") or ""
    if device_id and agg.first_device_id is None:
        agg.first_device_id = device_id

    agg.evidence_rows.append(row)


def aggregate_alerts(
    input_dir: Path, max_rows_per_file: int
) -> tuple[dict[str, AlertAgg], dict[str, int]]:
    """Stream both CSVs (Train then Test) into one combined pool of per-alert aggregates.

    `max_rows_per_file <= 0` means unlimited (read the whole file). Progress is printed to
    stderr every `PROGRESS_EVERY` rows since a full-dataset run can take a long time.
    """
    alerts: dict[str, AlertAgg] = {}
    file_row_counts: dict[str, int] = {}

    for filename in CSV_FILES:
        path = input_dir / filename
        if not path.exists():
            print(f"WARNING: {path} not found, skipping", file=sys.stderr)
            continue

        count = 0
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                _aggregate_row(alerts, row)
                count += 1
                if count % PROGRESS_EVERY == 0:
                    print(f"[{filename}] processed {count:,} rows...", file=sys.stderr)
                if max_rows_per_file and count >= max_rows_per_file:
                    break

        file_row_counts[filename] = count
        cap_note = "capped by --max-rows-per-file" if max_rows_per_file and count >= max_rows_per_file else "full file read"
        print(f"[{filename}] finished: {count:,} rows read ({cap_note})", file=sys.stderr)

    return alerts, file_row_counts


def resolve_ground_truth_label(votes: Counter) -> Optional[str]:
    """Majority-vote an alert's rows' IncidentGrade values into Jev's vocabulary.

    Returns None if an alert had no non-empty IncidentGrade on any of its rows at all (rare edge
    case; such alerts are still emitted with `ground_truth_label: null` rather than dropped, and
    are excluded from the train-only FP-rate computation in Step 3 since they can't be counted as
    FP or not-FP).
    """
    if not votes:
        return None
    max_count = max(votes.values())
    tied = [grade for grade, c in votes.items() if c == max_count]
    winner = tied[0] if len(tied) == 1 else next(g for g in GRADE_PRIORITY if g in tied)
    return GRADE_MAP.get(winner)


# ---------------------------------------------------------------------------------------------
# Step 2: deterministic incident-level split
# ---------------------------------------------------------------------------------------------


def compute_incident_splits(
    incident_ids: set[str], train_frac: float, val_frac: float
) -> dict[str, str]:
    """Assign every incident_id to train/val/test via a stable hash bucket.

    `int(sha256(incident_id), 16) % 100` is deterministic and reproducible across runs without
    needing to enumerate all incidents up front (streaming-friendly in spirit, even though this
    implementation does hold the (small, alert-count-bounded) set of unique incident IDs seen in
    this run in memory to build the mapping once).
    """
    train_boundary = round(train_frac * 100)
    val_boundary = round((train_frac + val_frac) * 100)

    splits: dict[str, str] = {}
    for incident_id in incident_ids:
        bucket = int(hashlib.sha256(incident_id.encode("utf-8")).hexdigest(), 16) % 100
        if bucket < train_boundary:
            splits[incident_id] = "train"
        elif bucket < val_boundary:
            splits[incident_id] = "val"
        else:
            splits[incident_id] = "test"
    return splits


def verify_incident_split_integrity(
    alerts: dict[str, AlertAgg], alert_splits: dict[str, str]
) -> None:
    """Assert no incident_id's alerts ended up split across more than one bucket."""
    incident_to_splits: dict[str, set[str]] = defaultdict(set)
    for alert_id, agg in alerts.items():
        incident_to_splits[agg.incident_id].add(alert_splits[alert_id])

    offenders = {inc: s for inc, s in incident_to_splits.items() if len(s) > 1}
    assert not offenders, f"Incident(s) spanning multiple splits: {list(offenders.items())[:5]}"
    print(
        f"Verified: all {len(incident_to_splits):,} incidents map to exactly one split.",
        file=sys.stderr,
    )


# ---------------------------------------------------------------------------------------------
# Step 3: train-only rule_historical_fp_rate table
# ---------------------------------------------------------------------------------------------


def compute_fp_rate_table(
    alerts: dict[str, AlertAgg],
    alert_labels: dict[str, Optional[str]],
    alert_splits: dict[str, str],
) -> dict[str, float]:
    """Per-detector empirical FP rate, computed from the TRAIN split only (no leakage).

    Applied to all three splits at lookup time in `build_state_object`. Detectors with zero train
    occurrences simply aren't keys in the returned dict; `rule_historical_fp_rate` (imported from
    feature-builder) already documents and clamps to 0.0 for missing lookup entries, so that
    default is reused rather than reimplemented here.
    """
    totals: Counter = Counter()
    false_positives: Counter = Counter()

    for alert_id, agg in alerts.items():
        if alert_splits[alert_id] != "train":
            continue
        label = alert_labels[alert_id]
        if label is None:
            continue  # can't count an unresolvable grade as FP or not-FP
        totals[agg.detector_id] += 1
        if label == "false_positive":
            false_positives[agg.detector_id] += 1

    return {
        detector_id: false_positives[detector_id] / total
        for detector_id, total in totals.items()
    }


# ---------------------------------------------------------------------------------------------
# similar_alerts_24h index (structural, not a label — computed across ALL splits together)
# ---------------------------------------------------------------------------------------------


def build_similar_alerts_index(alerts: dict[str, AlertAgg]) -> dict[str, int]:
    """Count of other alerts sharing (org_id, detector_id) within +/-24h, per alert.

    Grouped by (org_id, detector_id), each group's timestamps sorted once, then `bisect` used per
    alert to find its window's bounds — O(n log n) total, not an O(n^2) all-pairs scan.
    """
    groups: dict[tuple[str, str], list[tuple[datetime, str]]] = defaultdict(list)
    for alert_id, agg in alerts.items():
        groups[(agg.org_id, agg.detector_id)].append((agg.timestamp, alert_id))

    index: dict[str, int] = {}
    window = timedelta(hours=24)
    for items in groups.values():
        items.sort(key=lambda pair: pair[0])
        timestamps = [ts for ts, _ in items]
        for ts, alert_id in items:
            lo = bisect.bisect_left(timestamps, ts - window)
            hi = bisect.bisect_right(timestamps, ts + window)
            index[alert_id] = (hi - lo) - 1  # exclude the alert itself
    return index


def build_first_seen_index(alerts: dict[str, AlertAgg]) -> dict[str, int]:
    """`src_ip_first_seen_days` per alert: days since `first_ip` (per-alert entity, from
    `AlertAgg.first_ip`) was first seen in this loaded dataset, as of that alert's own timestamp.

    Structural, not label-derived (same rationale as `similar_alerts_24h` above) -- computed
    across ALL splits together, no leakage risk. Grouped by `first_ip`, each group's timestamps
    sorted once, then each alert looks up the group's minimum timestamp up to and including its
    own -- O(n log n) via a running min over the sorted list, not per-alert rescanning.

    Alerts with no `first_ip` (GUIDE's `IpAddress` column was empty for every row contributing to
    that alert -- a real, if uncommon, case) get 0, the same "just seen"/most-suspicious default
    `derived_fields.py` documents for a missing lookup entry -- not a special case here.
    """
    groups: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    for alert_id, agg in alerts.items():
        if agg.first_ip:
            groups[agg.first_ip].append((agg.timestamp, alert_id))

    index: dict[str, int] = {}
    for items in groups.values():
        items.sort(key=lambda pair: pair[0])
        first_seen = items[0][0]  # earliest timestamp in the group, since items is sorted
        for ts, alert_id in items:
            index[alert_id] = (ts - first_seen).days  # always >= 0, items[0] itself gives 0
    return index


# ---------------------------------------------------------------------------------------------
# Step 4: build the Jev state object
# ---------------------------------------------------------------------------------------------


def build_state_object(
    agg: AlertAgg, fp_rate_table: dict[str, float], similar_count: int, first_seen_days: int
) -> dict:
    return {
        "alert": {
            "source": "guide_replay",
            "rule_id": agg.detector_id,
            "rule_description": f"guide_alert_title_id:{agg.alert_title_id}",
            "rule_level": None,
            "mitre_hint": sorted(agg.mitre_techniques),
            "timestamp_utc": format_iso_z(agg.timestamp),
        },
        "entities": {
            "src_ip": agg.first_ip,
            "user": agg.user,
            "host": agg.host,
        },
        "derived": {
            "failed_auth_10m": 0,
            "successful_auth_after_failures": False,
            "off_hours": off_hours(agg.timestamp),
            "src_ip_first_seen_days": first_seen_days,
            "src_ip_reputation": "unknown",
            "host_criticality": "unknown",
            "rule_historical_fp_rate": rule_historical_fp_rate(agg.detector_id, fp_rate_table),
            "similar_alerts_24h": similar_count,
        },
        "untrusted_evidence": {
            "raw_log_excerpt": "",
        },
    }


# ---------------------------------------------------------------------------------------------
# Step 5: write output
# ---------------------------------------------------------------------------------------------


def write_outputs(
    alerts: dict[str, AlertAgg],
    alert_labels: dict[str, Optional[str]],
    alert_splits: dict[str, str],
    fp_rate_table: dict[str, float],
    similar_index: dict[str, int],
    first_seen_index: dict[str, int],
    output_dir: Path,
) -> tuple[dict[str, Counter], int]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "train": output_dir / "guide_train.jsonl",
        "val": output_dir / "guide_val.jsonl",
        "test": output_dir / "guide_test.jsonl",
    }
    handles = {split: path.open("w", encoding="utf-8") for split, path in paths.items()}

    label_dist: dict[str, Counter] = {"train": Counter(), "val": Counter(), "test": Counter()}
    skipped_no_label = 0

    try:
        for alert_id, agg in alerts.items():
            split = alert_splits[alert_id]
            label = alert_labels[alert_id]
            if label is None:
                skipped_no_label += 1

            state = build_state_object(
                agg, fp_rate_table, similar_index.get(alert_id, 0), first_seen_index.get(alert_id, 0)
            )
            record = {
                "source": "guide_replay",
                "external_id": f"guide-alert-{alert_id}",
                "incident_id": agg.incident_id,
                "raw": {"evidence_rows": agg.evidence_rows},
                "normalized": state,
                "ground_truth_label": label,
            }
            handles[split].write(json.dumps(record) + "\n")
            label_dist[split][label if label is not None else "null"] += 1
    finally:
        for fh in handles.values():
            fh.close()

    return label_dist, skipped_no_label


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert the Microsoft GUIDE dataset into Jev state-object .jsonl files."
    )
    parser.add_argument(
        "--input-dir",
        default="data/datasets/guide",
        help="Directory containing GUIDE_Train.csv and GUIDE_Test.csv (default: data/datasets/guide)",
    )
    parser.add_argument(
        "--output-dir",
        default="data/datasets/guide",
        help="Directory to write guide_{train,val,test}.jsonl into (default: data/datasets/guide)",
    )
    parser.add_argument(
        "--max-rows-per-file",
        type=int,
        default=200_000,
        help="Cap on data rows read per input CSV. 0 means unlimited (read the whole file). "
        "Default 200000 keeps the ~13.6M-row combined dataset within typical dev-laptop memory.",
    )
    parser.add_argument(
        "--train-frac",
        type=float,
        default=0.70,
        help="Fraction of incidents assigned to the train split (default: 0.70)",
    )
    parser.add_argument(
        "--val-frac",
        type=float,
        default=0.15,
        help="Fraction of incidents assigned to the val split (default: 0.15). "
        "Test fraction is implicit: 1 - train_frac - val_frac.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    test_frac = 1.0 - args.train_frac - args.val_frac
    if test_frac <= 0 or args.train_frac <= 0 or args.val_frac <= 0:
        parser.error("--train-frac and --val-frac must each be > 0 and sum to < 1.0")

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)

    t0 = time.time()

    # Step 1
    alerts, file_row_counts = aggregate_alerts(input_dir, args.max_rows_per_file)
    total_rows = sum(file_row_counts.values())
    print(f"Aggregated {total_rows:,} rows into {len(alerts):,} alerts.", file=sys.stderr)

    # Step 2
    incident_ids = {agg.incident_id for agg in alerts.values()}
    incident_splits = compute_incident_splits(incident_ids, args.train_frac, args.val_frac)
    alert_splits = {
        alert_id: incident_splits[agg.incident_id] for alert_id, agg in alerts.items()
    }
    verify_incident_split_integrity(alerts, alert_splits)

    alert_labels = {
        alert_id: resolve_ground_truth_label(agg.grade_votes) for alert_id, agg in alerts.items()
    }

    # Step 3
    fp_rate_table = compute_fp_rate_table(alerts, alert_labels, alert_splits)

    # similar_alerts_24h / src_ip_first_seen_days indices (structural; computed across all
    # splits together -- see build_similar_alerts_index's docstring for why that's leak-safe)
    similar_index = build_similar_alerts_index(alerts)
    first_seen_index = build_first_seen_index(alerts)

    # Step 5 (writes files)
    label_dist, skipped_no_label = write_outputs(
        alerts, alert_labels, alert_splits, fp_rate_table, similar_index, first_seen_index, output_dir
    )

    elapsed = time.time() - t0

    split_incident_counts = Counter(incident_splits.values())
    split_alert_counts = Counter(alert_splits.values())

    print("\n=== guide_to_state.py run summary ===", file=sys.stderr)
    for fname, cnt in file_row_counts.items():
        print(f"  {fname}: {cnt:,} rows read", file=sys.stderr)
    print(f"  total rows processed: {total_rows:,}", file=sys.stderr)
    print(f"  total alerts: {len(alerts):,}", file=sys.stderr)
    print(f"  total incidents: {len(incident_ids):,}", file=sys.stderr)
    print(f"  detectors with a train-derived fp-rate entry: {len(fp_rate_table):,}", file=sys.stderr)
    for split in ("train", "val", "test"):
        print(
            f"  {split}: {split_alert_counts[split]:,} alerts, "
            f"{split_incident_counts[split]:,} incidents, "
            f"label dist: {dict(label_dist[split])}",
            file=sys.stderr,
        )
    print(f"  alerts with no resolvable ground_truth_label: {skipped_no_label:,}", file=sys.stderr)
    print(f"  wall-clock time: {elapsed:.1f}s", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
