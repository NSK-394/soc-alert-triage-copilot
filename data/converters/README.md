# data/converters

Phase A task 4 (`docs/architecture.md` §7 and §12). Converts source datasets into the Jev
state-object `.jsonl` format that `data/replay-harness` streams into ingest-api. Only
`guide_to_state.py` exists so far; `cicids_suricata_replay.py` (§7 item 3, optional) is not built.

## `guide_to_state.py`

Converts the Microsoft GUIDE security-incident dataset (`GUIDE_Train.csv` + `GUIDE_Test.csv`) into
`guide_train.jsonl`, `guide_val.jsonl`, `guide_test.jsonl` matching the replay-harness `.jsonl`
contract (`data/replay-harness/README.md`) and the state-object shape in `docs/architecture.md`
§4.

### Usage

```bash
python data/converters/guide_to_state.py \
  --input-dir data/datasets/guide \
  --output-dir data/datasets/guide \
  --max-rows-per-file 200000 \
  --train-frac 0.70 \
  --val-frac 0.15
```

| Flag | Default | Meaning |
|---|---|---|
| `--input-dir` | `data/datasets/guide` | Directory containing `GUIDE_Train.csv` and `GUIDE_Test.csv`. |
| `--output-dir` | `data/datasets/guide` | Directory to write the three `.jsonl` files into. |
| `--max-rows-per-file` | `200000` | Cap on data rows read per input CSV. `0` = unlimited (read the whole file). The combined dataset is ~13.6M rows (9,516,837 Train + 4,147,992 Test), impractical to aggregate fully in memory on a typical dev laptop — this cap is a deliberate, documented trade-off, not a bug. Actual rows/alerts/incidents processed are always printed at the end of the run. |
| `--train-frac` | `0.70` | Fraction of **incidents** assigned to train. |
| `--val-frac` | `0.15` | Fraction of incidents assigned to val. Test is implicit: `1 - train_frac - val_frac`. |

Both CSVs are streamed line-by-line with `csv.DictReader` — never loaded fully into memory.
Progress is printed to stderr every 50,000 rows.

### Key design decisions

- **Microsoft's own Train/Test file boundary is not used as the split.** Both CSVs are pooled
  into one combined set of alerts, which is then re-split ourselves. We need a held-out
  *validation* split for policy-threshold sweeping (`docs/architecture.md` §8) that Microsoft's
  2-file layout doesn't provide.
- **Split is incident-level, not row- or alert-level.** Every alert belonging to the same
  `IncidentId` lands in the same split, via a deterministic hash bucket
  (`sha256(incident_id) % 100`), computed without needing to enumerate all incidents in a separate
  pre-pass. This avoids the label leakage a prior public GUIDE benchmark found when splitting by
  row or by alert (same incident's rows/alerts are highly correlated — same attacker, same
  entities, near-identical timestamps).
- **`derived.rule_historical_fp_rate` is computed from the train split only**, then applied to all
  three splits — val/test never contribute to the rate they're scored with. Detectors with zero
  train occurrences default to `0.0` (reuses `services/feature-builder`'s own
  `rule_historical_fp_rate`, which documents and clamps to that same default).
- **`derived.similar_alerts_24h`** is a structural count (not a label, so it doesn't leak
  ground truth) of other alerts sharing `(org_id, detector_id)` within ±24h, computed per group
  with `bisect` over a sorted timestamp list (O(n log n)), not an O(n²) scan.
- **`derived.off_hours`** is reused from `services/feature-builder/derived_fields.py` (via a
  `sys.path` workaround, since the hyphenated directory name blocks a normal dotted import), not
  reimplemented.

### What's real vs. defaulted in the output

Real, computed per-alert:

- `alert.rule_id`, `alert.mitre_hint`, `alert.timestamp_utc`, `entities.*`
- `derived.off_hours` — real calendar arithmetic on the alert's actual timestamp
- `derived.rule_historical_fp_rate` — real, train-split-only empirical FP rate per detector
- `derived.similar_alerts_24h` — real structural count, see above
- `ground_truth_label` — majority vote of the alert's rows' `IncidentGrade`, tie-broken toward the
  more severe label (`TruePositive` > `BenignPositive` > `FalsePositive`) on an exact tie

Genuinely not computable from GUIDE, left at documented, conservative defaults (do not treat these
as real signal if this dataset is used to sanity-check anything downstream):

| Field | Default | Why |
|---|---|---|
| `alert.rule_level` | `null` | GUIDE has no severity/level column analogous to Wazuh's `rule_level`. |
| `alert.rule_description` | `"guide_alert_title_id:<id>"` | GUIDE's `AlertTitle` is an anonymized numeric ID, not human-readable rule text — prefixed so it's obviously not real prose. |
| `derived.failed_auth_10m` | `0` | GUIDE has no raw auth-event log stream. |
| `derived.successful_auth_after_failures` | `false` | Same — no raw auth-event stream. |
| `derived.src_ip_first_seen_days` | `0` | No IP-history data; `0` ("just seen") is the suspicious reading, matching feature-builder's own convention. |
| `derived.src_ip_reputation` | `"unknown"` | No IP reputation feed. |
| `derived.host_criticality` | `"unknown"` | No asset-criticality inventory. |
| `untrusted_evidence.raw_log_excerpt` | `""` | GUIDE has no raw log text field. Left empty rather than fabricating adversarial-looking text — the prompt-injection test suite (later phase) uses purpose-built synthetic fixtures instead. |

### Other known limitations

- Up to ~1,000 alerts per 400k-row run have no resolvable `ground_truth_label` (none of their rows
  had a non-empty `IncidentGrade`). These are still emitted with `"ground_truth_label": null`
  rather than dropped, and are excluded from the train-only FP-rate computation.
  `--max-rows-per-file` truncates mid-file, so an alert whose rows straddle the cutoff may have
  incomplete `raw.evidence_rows` (its later rows past the cutoff are simply never seen).
- `AlertId`/`IncidentId`/`DetectorId`/etc. are GUIDE's raw anonymized numeric-string IDs, used
  as-is — they are not human-readable and are not translated into anything more meaningful here.
