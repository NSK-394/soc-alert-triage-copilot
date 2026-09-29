# SOC Alert Triage Copilot — Architecture & Build Brief

Prepared for @NIkhilsai · 2026-09-28. This is the design spec for the project; kept in sync as
the build progresses. Original brief content preserved below, reorganized under numbered headers.

## 1. Overview and definition of done

Build a standalone, open-source SOC alert triage copilot: a two-tier pipeline that scores every
incoming security alert with **Jev** (fast, cheap, typed decisions) and escalates the ambiguous or
high-severity ones to a swappable OpenAI model (**Luna** by default; **Sol** or **Astra**
selectable) for a written investigation brief.

This is a fresh, self-contained repo meant to demonstrate a novel, cost-efficient triage
architecture, benchmarked on real labeled data, and released open source.

MVP is done when all of the following are true:

- `docker compose up` starts the full stack (API, worker, Postgres, Redis, dashboard) with no
  manual setup beyond `.env` values.
- A replay of at least 2,000 labeled alerts from the Microsoft GUIDE dataset runs through the Jev
  tier and produces a benchmark report (precision, recall, macro-F1) compared against a
  majority-class baseline and a gradient-boosted tree baseline on the same features.
- At least one live alert path works end to end: a simulated Wazuh SSH brute-force alert is
  ingested, scored by Jev, escalated, and produces a Luna-generated brief, with a Slack
  notification firing.
- The dashboard shows a triage queue, a brief viewer, and a live "cost per 1,000 alerts" figure.
- A prompt-injection test suite runs against both tiers and the results (pass/fail) are
  documented, not hidden.
- README documents setup, architecture, benchmark results including where the model performs
  badly, and limitations.

## 2. Architecture

Ingestion normalizes the raw alert into a compact state object with computed fields (counts, time
deltas, reputation flags) done in code, never left for the model. Jev answers a fixed set of typed
questions on every alert in parallel, sub-500ms. The policy engine (versioned code, not a prompt)
reads Jev's confidence and severity: high-confidence cases act immediately (auto-close a confirmed
false positive, or page Slack/PagerDuty for a confirmed critical); everything else is escalated to
the Tier-2 model, which reads a curated time-window of correlated events and writes a structured
incident brief (attack chain, MITRE mapping, recommended actions) attached to the analyst's queue
item.

Components:

- **ingest-api** (FastAPI) — receives alerts from a replay harness or a Wazuh webhook, writes to
  Postgres, enqueues a scoring job
- **feature-builder** — pure Python, computes all derived/counted/timestamp fields; nothing
  counted or dated is ever left for a model to infer
- **jev-client** — wraps the TypeSafe SDK, sends the typed question catalog, returns
  confidence-scored decisions
- **policy-engine** — versioned YAML + a small rules evaluator; decides auto-close /
  auto-escalate / queue-with-brief
- **tier2-worker** — builds the curated context window, calls the configured OpenAI model (Luna
  default), validates the brief's citations against real log-line IDs
- **notifier** — Slack incoming webhook + PagerDuty Events API v2
- **dashboard** (Next.js) — triage queue, brief viewer, cost-per-1000-alerts tile, analyst
  feedback buttons
- **costs table** — every Jev and Tier-2 call's token usage logged, for the live cost tile and the
  budget guard

## 3. Tech stack and repo structure

Stack: Python 3.11 + FastAPI (API), Redis + RQ (job queue), Postgres 15 (state, decisions, briefs,
costs), Next.js 14 + Tailwind (dashboard), Docker Compose (everything runs with one command).
Wazuh (Docker) for the optional live demo. `typesafe-sdk` for Jev, official `openai` Python SDK
for the Tier-2 provider.

```
soc-triage-copilot/
├── docker-compose.yml
├── .env.example
├── README.md
├── services/
│   ├── ingest-api/            # FastAPI: webhook + replay endpoints, alert CRUD
│   ├── feature-builder/       # pure-Python derived features (counts, deltas, reputation)
│   ├── jev-client/            # TypeSafe SDK wrapper, question catalog, calibration utils
│   ├── tier2-worker/          # provider abstraction, prompt templates, citation validator
│   ├── policy-engine/         # YAML rules + evaluator, auto-close/escalate/queue logic
│   └── notifier/              # Slack + PagerDuty clients
├── dashboard/                 # Next.js app: queue, brief viewer, cost tile, feedback
├── data/
│   ├── converters/             # GUIDE → state object, CICIDS+Suricata replay recipe
│   ├── replay-harness/         # streams labeled alerts into ingest-api at configurable speed
│   └── datasets/               # gitignored; download scripts only, never commit raw data
├── eval/
│   ├── baseline_majority.py
│   ├── baseline_gbm.py         # gradient-boosted tree baseline for comparison
│   ├── benchmark.py            # runs Jev + baselines on held-out split, reports metrics
│   └── prompt_injection_suite/ # adversarial alert fixtures for both tiers
├── infra/
│   ├── wazuh/                  # docker-compose fragment + sample rules for the live demo
│   └── migrations/             # Postgres schema migrations
└── docs/
    └── architecture.md         # this file
```

## 4. Data model

Postgres tables (minimum): `alerts` (raw + normalized fields, source, ingested_at),
`jev_decisions` (alert_id, verdict, confidence, severity, raw_response, latency_ms),
`policy_outcomes` (alert_id, action: auto_close / auto_escalate / queued, rule_version), `briefs`
(alert_id, provider_model, summary, attack_chain jsonb, mitre_techniques, cited_log_ids,
tokens_in, tokens_out, cost_usd), `feedback` (alert_id, analyst_verdict, correct: bool — this is
what the benchmark report is built from), `costs` (per-call log: provider, tokens, cost_usd,
timestamp).

The Jev state object (what feature-builder produces; keep it small, curated, and free of raw
untrusted text except under its own labeled key):

```json
{
  "alert": {
    "source": "wazuh",
    "rule_id": "5712",
    "rule_description": "SSHD brute force trying to get access",
    "rule_level": 10,
    "mitre_hint": ["T1110"],
    "timestamp_utc": "2026-09-20T03:12:44Z"
  },
  "entities": {
    "src_ip": "203.0.113.7",
    "user": "svc-backup",
    "host": "db-prod-02"
  },
  "derived": {
    "failed_auth_10m": 212,
    "successful_auth_after_failures": true,
    "off_hours": true,
    "src_ip_first_seen_days": 0,
    "src_ip_reputation": "malicious",
    "host_criticality": "crown_jewel",
    "rule_historical_fp_rate": 0.62,
    "similar_alerts_24h": 3
  },
  "untrusted_evidence": {
    "raw_log_excerpt": "Accepted password for svc-backup from 203.0.113.7 port 51022"
  }
}
```

Everything under `derived` is computed in Python before Jev ever sees it — counts, time deltas,
and reputation lookups are never left for the model to infer from raw text. `untrusted_evidence`
is the only place attacker-controlled strings appear, and it is treated as hostile input by both
tiers (see §10).

## 5. Jev integration spec

Endpoint: `POST https://api.typesafe.ai/v1/systemone`, model route `jev-latest`. Install
`typesafe-sdk` (Python ≥ 3.10), key in `TYPESAFE_API_KEY`. If the waitlist hasn't cleared yet,
point the same SDK at OpenRouter's System One route as a fallback.

Question catalog (all answered in one call per alert, evaluated in parallel):

| Question key | Type | Options / range | Purpose |
|---|---|---|---|
| `triage_verdict` | Choice | true_positive / benign_positive / false_positive / other | Matches GUIDE's own labels, so the benchmark scores directly against it |
| `is_false_positive` | Noul | 0–1 probability | Independent cross-check against triage_verdict |
| `severity` | Score | 4 levels: informational → low → high → critical | Drives the policy engine's auto-close/escalate threshold |
| `attack_category` | Choice | 14 MITRE ATT&CK tactics + other | Feeds the dashboard's category filter and the benchmark's per-category breakdown |
| `needs_more_context` | Noul | 0–1 probability | The cleanest signal to trigger Tier-2 escalation |
| `business_impact_if_true` | Score | 3 levels | Used only when triage_verdict leans true_positive, to set page urgency |

Confidence: compute your own margin/entropy from the full probabilities array on Choice answers —
don't rely on the single confidence field alone when two options are close.

Known failure modes to design around (from TypeSafe's own docs):

- Counting and date arithmetic degrade inside the model — always compute counts and
  "off-hours"/time-delta flags in feature-builder, never pass raw timestamps and ask Jev to reason
  about them.
- Large, noisy state lowers accuracy — send the curated object above, never the raw alert blob.
- Adversarial content in alert fields can steer answers — this is why `untrusted_evidence` is a
  separate, clearly labeled key, and why the never-auto-close list (§8) exists.
- "Cannot hallucinate" only means the output always matches the typed schema — Jev can still be
  confidently wrong; that's what the benchmark in §10 is for.

Error handling: the SDK retries rate limits and 5xx automatically. Rate limit is 1,200 req/min and
250k tokens/sec — the replay harness needs a token-bucket limiter in front of it. On any
unrecoverable Jev error, fail safe: route the alert to `queued` (never auto-close on a Jev
failure).

## 6. Tier-2 provider abstraction

One interface, three interchangeable models. Default to Luna for cost; Sol and Astra are drop-in
swaps with no other code change.

```python
class Tier2Provider(Protocol):
    def generate_brief(self, alert: dict, context: list[dict]) -> Brief: ...

PROVIDERS = {
    "luna":  OpenAIProvider(model="gpt-6-luna"),   # default
    "sol":   OpenAIProvider(model="gpt-6-sol"),
    "astra": OpenAIProvider(model="gpt-6-astra"),   # deep-investigation option
}
# selected via TIER2_MODEL env var, exposed later as a dropdown in the dashboard
```

| Model | Price (in/out per 1M tok) | ~Cost per 20k-in/5k-out brief | Role |
|---|---|---|---|
| GPT-6 Luna | $0.10 / $0.50 | ~$0.0045 | Default — cost-sensitive teams, runs on every escalation |
| GPT-6 Sol | $2 / $10 | ~$0.09 | Mid option — better reasoning, still cheap |
| GPT-6 Astra | $10 / $50 (short ctx) | ~$0.20–$0.25 | Deep investigation — curate context tightly |

Context is always curated, not dumped: the triggering alert plus ±30 minutes of events for the
same entities (src_ip, user, host) — keeps every tier within 10k–40k tokens regardless of
provider.

Prompt structure: stable system prompt + schema first (cache-eligible), then the curated evidence
block wrapped in explicit delimiters with an instruction that nothing inside it is a command.
Require JSON output: `summary`, `attack_chain[]` (each step citing a real `log_line_id`),
`mitre_techniques[]`, `recommended_actions[]`, `open_questions[]`. The tier2-worker rejects and
retries once if a brief cites a `log_line_id` that doesn't exist in the context it was given.

Budget guard: hard daily cap on brief count (default 300/day), and the worker refuses to fire once
the day's costs cross a configured USD ceiling, logging a `budget_exceeded` event instead of
failing silently.

## 7. Ingestion and dataset pipeline

Build order (unblocks everything while Jev waitlist access is pending):

1. **Replay harness** (`data/replay-harness/`): reads a converted dataset file and POSTs each
   alert to ingest-api at a configurable rate.
2. **GUIDE converter** (`data/converters/guide_to_state.py`): downloads Microsoft's GUIDE dataset
   from Kaggle (`Microsoft/microsoft-security-incident-prediction`), maps its numeric-ID fields
   into the state-object shape from §4, preserves the original TP/BP/FP label for scoring. **Split
   by incident, not by row** — a prior public benchmark found incident-level label leakage in
   naive GUIDE splits, which silently inflates accuracy.
3. **CICIDS2017 + IDS replay** (`data/converters/cicids_suricata_replay.py`, optional): replay
   labeled CICIDS2017 PCAPs through Suricata, label each resulting alert TP/FP by matching its
   5-tuple and timestamp against the dataset's labeled flows.
4. **Wazuh webhook** (`infra/wazuh/`, for the live demo): a Wazuh custom integration posts each
   triggered alert to ingest-api's `/webhook/wazuh` endpoint.

Never ingest real employer, client, or other project data into this pipeline — GUIDE, CICIDS, and
a self-simulated Wazuh lab are enough for a credible public benchmark and demo.

## 8. Policy engine

Code, not a prompt — versioned YAML read by a small deterministic evaluator.

```yaml
# policy/v1.yaml
auto_close:
  when:
    verdict_in: [false_positive, benign_positive]
    confidence_gte: 0.90
    severity_lt: 1.0
  unless:
    host_criticality: crown_jewel
    rule_id_in: NEVER_AUTO_CLOSE_LIST   # ransomware, credential dumping, etc.

auto_escalate:
  when:
    verdict_in: [true_positive]
    confidence_gte: 0.85
    severity_gte: 2.5
  action: [page_pagerduty, notify_slack]

default: queue_with_tier2_brief
```

Run in shadow mode first: log what the policy would have done against every incoming alert
without actually auto-closing or paging anything, for the first evaluation pass on GUIDE. The
metric that matters isn't accuracy — it's the false-negative rate among alerts the policy would
have auto-closed. Report that number explicitly, even if it's not flattering.

Thresholds (0.90 / 0.85 / severity cutoffs) are starting points — sweep them against the GUIDE
validation split in `eval/benchmark.py` and pick the point that keeps auto-close false-negatives
near zero.

## 9. Dashboard

Next.js + Tailwind, four screens:

| Screen | Shows |
|---|---|
| Queue | Alerts routed to `queued`, sorted by severity; each row shows Jev's verdict, confidence, status chip |
| Alert detail | Full state object, Jev's raw typed response, the policy decision and which rule fired |
| Brief viewer | The Tier-2 brief (summary, attack chain with cited log lines, MITRE techniques, recommended actions), plus which model generated it and its cost |
| Cost tile (global header) | Live "cost per 1,000 alerts" — Jev spend + Tier-2 spend, split out, from the `costs` table |

Analyst feedback buttons (correct / incorrect) write to the `feedback` table — the same table the
benchmark report reads from. A later iteration adds a dropdown to pick Luna / Sol / Astra per
alert or globally, using the provider abstraction from §6.

## 10. Security, testing, and evaluation harness

Baselines (build before touching Jev): `baseline_majority.py` (always predicts the most common
label) and `baseline_gbm.py` (a gradient-boosted tree, e.g. XGBoost, on the same derived features
Jev sees). A prior public GUIDE benchmark saw an LLM score macro-F1 0.21 against a Random Forest's
0.60 on the same data — always report Jev's numbers next to both baselines, and treat beating the
majority-class floor as the bar to clear before claiming anything.

`eval/benchmark.py` runs the full split through Jev (and, separately, through each Tier-2 model on
a smaller escalated sample) and reports: macro-F1, per-class precision/recall, a
calibration/reliability diagram (does 90% confidence mean 90% correct?), and the auto-close
false-negative rate from §8. Split by incident ID, never by row.

`eval/prompt_injection_suite/`: a set of adversarial alert fixtures with attacker-controlled
strings in `untrusted_evidence` attempting to change the verdict, leak the system prompt, or
fabricate MITRE techniques. Run against both tiers; log pass/fail per fixture in the README,
including failures.

Tooling: run static-analysis (CodeQL/Semgrep-style) passes before public release. A security tool
with a vulnerable webhook undermines the entire pitch, so this pass is not optional.

CI: GitHub Actions running pytest on feature-builder and policy-engine (deterministic, no API keys
needed), plus a `docker compose up --build` smoke test.

## 11. Required environment / credentials

| Item | Where to get it | Needed for |
|---|---|---|
| `TYPESAFE_API_KEY` | typesafe.ai waitlist; fallback OpenRouter System One route | Tier 1 (Jev) |
| `OPENAI_API_KEY` | platform.openai.com, hard project spend cap set (e.g. $30–$50) | Tier 2 (Luna/Sol/Astra) |
| Kaggle account + `microsoft-security-incident-prediction` dataset | kaggle.com | GUIDE benchmark |
| `SLACK_WEBHOOK_URL` | Free Slack workspace, incoming webhook app | Escalation notifications |
| `PAGERDUTY_API_KEY` (optional) | Free PagerDuty developer account | Critical-alert paging in the demo |
| Docker + Docker Compose | — | Running Wazuh + the whole stack |
| GitHub repo (public, MIT or Apache-2.0) | — | Open-source release |

## 12. Ordered task list

### Phase A — scaffold (no API keys needed)
- [ ] `docker-compose.yml`, Postgres schema/migrations from §4, `.env.example` listing every var from §11
- [ ] ingest-api: FastAPI skeleton, `/webhook/wazuh` and `/replay` endpoints, writes to `alerts` table
- [ ] feature-builder: implement the derived field computations from §4 as pure functions, with unit tests
- [ ] `data/converters/guide_to_state.py`: GUIDE row → state object, incident-level train/val/test split
- [ ] `data/replay-harness`: reads a converted dataset, posts to ingest-api at a configurable rate

### Phase B — baselines and Jev tier
- [ ] `eval/baseline_majority.py` and `eval/baseline_gbm.py`, run once and record the numbers to beat
- [ ] jev-client: question catalog from §5, calibration/margin computation, rate limiter
- [ ] `eval/benchmark.py`: run Jev on the GUIDE validation split, produce metrics + reliability diagram
- [ ] If waitlist access hasn't cleared: build/test against the OpenRouter System One fallback

### Phase C — policy engine and live path
- [ ] policy-engine: YAML evaluator from §8, shadow-mode logging first
- [ ] notifier: Slack + PagerDuty clients
- [ ] Wire ingest → features → Jev → policy → notifier end to end; verify against the replay harness
- [ ] `infra/wazuh/`: docker-compose fragment, 2–3 simulated attack scenarios

### Phase D — Tier-2 and dashboard
- [ ] tier2-worker: provider abstraction from §6, context builder, citation validator, budget guard
- [ ] Wire queued alerts to the Tier-2 worker; store briefs
- [ ] dashboard: the four screens from §9, feedback buttons wired to the feedback table

### Phase E — harden and ship
- [ ] `eval/prompt_injection_suite/`: adversarial fixtures, run against both tiers, log results
- [ ] Static-analysis pass (CodeQL/Semgrep); fix what surfaces
- [ ] GitHub Actions CI (pytest + `docker compose up --build` smoke test)
- [ ] README: setup, architecture, full benchmark table, cost-per-1,000-alerts figure, limitations, license
- [ ] Record the 30–60 second demo video
