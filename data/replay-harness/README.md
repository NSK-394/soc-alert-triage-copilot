# replay-harness

Phase A task 5 (see `docs/architecture.md` §7 and §12). A CLI that reads a
converted, labeled dataset file and replays it into ingest-api's `/replay`
endpoint at a configurable rate.

This is the generic replay mechanism only. It does not know anything about
GUIDE, CICIDS, or any other specific dataset — it just streams whatever
`.jsonl` file it's pointed at. The not-yet-built `data/converters/guide_to_state.py`
is expected to produce files in exactly the format documented below.

## Install

```bash
cd data/replay-harness
pip install -r requirements.txt          # runtime only
pip install -r requirements-dev.txt      # + pytest, for running the tests
```

## Usage

```bash
python replay.py --input path/to/file.jsonl --url http://localhost:8000 --rate 20 --limit 2000
```

| Flag | Required | Default | Meaning |
|---|---|---|---|
| `--input` | yes | — | Path to a `.jsonl` file (format below). |
| `--url` | no | `http://localhost:8000` | ingest-api base URL. Requests go to `{url}/replay`. |
| `--rate` | no | `10.0` | Target alerts/sec, averaged over the run. `0` (or negative) disables throttling — send as fast as possible. |
| `--limit` | no | none | Stop after N valid records have been attempted. Handy for a quick smoke test against a multi-million-row dataset. |
| `--timeout` | no | `5.0` | Per-request HTTP timeout, in seconds. |

The tool streams the input file line by line — it never loads the whole file
into memory, so it's safe to point `--input` at a multi-gigabyte GUIDE export
even without `--limit` (though for anything beyond a smoke test you'll
usually want `--limit` while iterating).

On completion it prints a summary: total lines read, records attempted,
sent OK, failed (with the first few failures' line number / status / error
shown, not just a count), elapsed time, and the effective send rate achieved.
Exit code is `0` if every attempted record succeeded, `1` if any failed, `2`
if the input file couldn't be opened.

### Retries

Each record gets up to 3 attempts with short exponential backoff (0.5s, 1s)
before being counted as failed:

- **Retried** (transient): connection errors, timeouts, and any `5xx`
  response from ingest-api.
- **Not retried** (permanent): any `4xx` response — that means the record
  itself is bad (fails validation, etc.), not that the server is having a
  bad moment, so retrying it would just waste time and hide the real
  problem.

### Malformed / invalid lines

- Blank or whitespace-only lines are skipped silently.
- Lines that fail to parse as JSON are logged as a warning (with the line
  number) and skipped — they don't stop the run.
- Parsed lines that aren't a JSON object, or are missing either the
  `source` or `raw` key, are logged as a warning and skipped rather than
  sent to the API (so the API's error log doesn't fill up with 422s from
  garbage rows and true bad-record failures don't get lost in the noise).

## The `.jsonl` input format

**This is the contract.** Each line of the input file is exactly one
`/replay` request body — a single JSON object, one per line, no wrapping
array, no trailing commas. This is also the target format for
`data/converters/guide_to_state.py` (and any other future converter): a
converter's job is to emit a file in this shape; the replay harness's job is
to stream it into ingest-api unchanged.

```json
{"source": "guide_replay", "external_id": "guide-000123", "incident_id": "inc-045", "raw": {"...": "arbitrary object, the original row"}, "normalized": {"...": "the Jev state object shape from docs/architecture.md §4, or {} if not yet computed"}, "ground_truth_label": "true_positive"}
```

Field notes (mirrors the `/replay` contract in `docs/architecture.md` §7 /
the ingest-api spec — do not deviate, other components target this same
shape):

| Field | Type | Notes |
|---|---|---|
| `source` | string | **Required.** E.g. `"guide_replay"`. |
| `external_id` | string | Stable ID for idempotent re-runs. `/replay` is idempotent on `(source, external_id)`. |
| `incident_id` | string or `null` | Groups related alerts. |
| `raw` | object | **Required.** The original row, unmodified, arbitrary shape. |
| `normalized` | object | The Jev state object shape from `docs/architecture.md` §4, or `{}` if the converter hasn't computed it yet. |
| `ground_truth_label` | string or `null` | One of `true_positive`, `benign_positive`, `false_positive`, or `null`. |

The harness only hard-validates `source` and `raw` being present on a dict
before sending (matching the "must look like a replay record" requirement) —
it does not validate `ground_truth_label`'s enum or `normalized`'s inner
shape; that's ingest-api's job and would otherwise duplicate/drift from its
schema. A minimal valid line is just:

```json
{"source": "guide_replay", "raw": {}}
```

## Tests

```bash
cd data/replay-harness
pytest
```

Tests cover only the pure logic — the rate-limiter's sleep-time computation,
line parsing/validation, and retry-eligibility rules — plus `send_record`'s
retry control flow with `requests.Session` mocked out (`unittest.mock`) and
the backoff `sleep_func` stubbed to a no-op. No real ingest-api instance or
real network/wall-clock sleeping is required or used.
