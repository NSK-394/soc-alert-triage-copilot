# infra/wazuh

Phase C task 4 (see `docs/architecture.md` §7 task 4 and §12) -- the live-demo
Wazuh scenario simulation. This satisfies the MVP requirement: "a simulated
Wazuh SSH brute-force alert is ingested, scored by Jev, escalated, and
produces a Luna-generated brief, with a Slack notification firing."

Running a full real Wazuh manager/indexer/dashboard stack is heavy (multiple
GB of containers) and not needed to hit that bar -- the word "simulated" is
load-bearing. The supported, tested path is **`simulate.py` POSTing
realistic, Wazuh-shaped alert JSON directly at ingest-api's
`POST /webhook/wazuh` endpoint**. A full real Wazuh stack is available as an
optional, documented-as-optional secondary path (see below) for anyone who
wants a fuller demo later; it is not required and not part of this project's
tested path.

## Quickstart: simulate.py against a local ingest-api

From the repo root:

```bash
# 1. Start Postgres + Redis + ingest-api (only what simulate.py needs)
docker compose up postgres redis ingest-api

# 2. In another terminal, install simulate.py's one dependency (shared with
#    data/replay-harness -- if you've already set that up, you have this too)
pip install requests

# 3. Fire a scenario
python infra/wazuh/simulate.py --scenario ssh_brute_force --url http://localhost:8000
```

Expected output: a `201` (first delivery) or `200` (idempotent redelivery,
same Wazuh alert `id` already seen) with the created/existing alert's UUID in
the response body.

### CLI

```
python simulate.py --scenario {ssh_brute_force,sudo_abuse,new_listening_service,all} \
                    [--url http://localhost:8000] [--repeat N] [--timeout 10.0]
```

| Flag | Required | Default | Meaning |
|---|---|---|---|
| `--scenario` | yes | -- | Which fixture to fire, or `all` to fire all three in sequence. |
| `--url` | no | `http://localhost:8000` | ingest-api base URL. POSTs go to `{url}/webhook/wazuh`. |
| `--repeat` | no | `1` | Replay the scenario N times. When N > 1, each repeat gets a jittered `id` and `timestamp` (37s apart) so ingest-api's `(source, external_id)` unique index doesn't collapse them into one row -- useful for generating volume to exercise `similar_alerts_24h`-style features once feature-builder is wired in. |
| `--timeout` | no | `10.0` | Per-request HTTP timeout, in seconds. |

Only dependency: `requests` (already used by `data/replay-harness`, so nothing
new if you have that installed).

## The scenarios

Each fixture in `scenarios/` is a realistic Wazuh alert JSON object -- the
same shape a real Wazuh manager emits (`rule`, `agent`, `data`, `full_log`,
etc.), based on Wazuh's documented alert format. ingest-api stores the whole
object as-is in `alerts.raw`; feature-builder (a later phase) is what turns
`full_log` into `untrusted_evidence.raw_log_excerpt` and the rest into the
Jev state object from `docs/architecture.md` §4.

| Scenario | Rule | Level | What it represents |
|---|---|---|---|
| `ssh_brute_force.json` | `5712` -- "SSHD brute force trying to get access" | 10 | The MVP's canonical live-demo alert (`docs/architecture.md` §4's worked example): repeated SSH auth failures against `svc-backup` from `203.0.113.7`, culminating in a successful login on `db-prod-02`. MITRE `T1110` (Brute Force). |
| `sudo_abuse.json` | `100050` -- "Privilege escalation: sudo executed by non-administrative user account" (local/custom rule, `if_sid: 5402`) | 8 | A service account (`jenkins`) that shouldn't have interactive sudo access runs `sudo bash` to a root shell on `web-app-01`. MITRE `T1548.003` (Sudo and Sudo Caching). |
| `new_listening_service.json` | `100210` -- "Osquery: new listening network service detected on non-standard port" (local/custom rule) | 6 | Osquery's `port_listening_processes_events` table reports a new process bound to port `4444` (a classic default Metasploit listener port) from an unexpected path (`/tmp/.hidden/backdoor`) on `db-prod-02`. MITRE `T1571` (Non-Standard Port). |

Judgment calls: real Wazuh's default ruleset only ships a rule for the
brute-force case (`5712`, matched exactly to the architecture doc's `rule_id`
and description). The sudo and new-listening-service scenarios use
plausible **local/custom rule IDs** (Wazuh convention: `100000+` for
site-defined rules, commonly built with `if_sid` chaining off a stock rule --
`100050` chains off the real stock rule `5402`, "Successful sudo to ROOT
executed") rather than inventing fake stock rule IDs. Severities follow real
Wazuh conventions: brute force gets a high level (10) matching the
architecture doc; sudo abuse is mid-high (8) since it's a completed privilege
escalation, not just an attempt; the new-listening-service is lower/informational-to-medium
(6) since an unrecognized port alone is suspicious-but-ambiguous evidence,
not confirmed compromise -- exactly the kind of alert `needs_more_context`
(§5) should catch. No fixture embeds a prompt-injection payload; that's
`eval/prompt_injection_suite`'s job in a separate phase, not this one.

## Optional: the full real Wazuh stack

`docker-compose.wazuh.yml` in this directory is a **documented-as-optional**,
standalone fragment (not wired into the repo root's `docker-compose.yml`) for
anyone who wants a real Wazuh manager/indexer/dashboard instead of the JSON
fixtures above -- e.g. to demo a genuine agent-to-manager-to-alert pipeline.
It follows Wazuh's own published single-node quickstart pattern and requires
pulling a few Wazuh-maintained config/cert-generation files that aren't part
of this repo (see the comment block at the top of the file for exact steps
and the upstream link). It is heavy (multiple GB of images, several minutes
to start) and is **not required for, or exercised by, the MVP demo path** --
`simulate.py` against `ingest-api` directly is the supported and tested path.

Run it with:

```bash
docker compose -f infra/wazuh/docker-compose.wazuh.yml up
```
