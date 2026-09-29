-- dashboard/scripts/seed.sql
-- Realistic fake rows for local dashboard smoke-testing, per docs/architecture.md Â§4/Â§9.
-- Run against a throwaway local Postgres that already has infra/migrations/*.sql applied, e.g.:
--   docker run --name soc-dash-seed-pg -e POSTGRES_USER=soc -e POSTGRES_PASSWORD=soc_dev_password \
--     -e POSTGRES_DB=soc_triage -p 5433:5432 \
--     -v "$(pwd)/infra/migrations:/docker-entrypoint-initdb.d:ro" -d postgres:15-alpine
--   psql postgresql://soc:soc_dev_password@localhost:5433/soc_triage -f dashboard/scripts/seed.sql
--
-- None of this data exists yet in a real dev DB (the pipeline that populates these tables from
-- live traffic is a later phase) -- this is fixture data only, for exercising the UI.

BEGIN;

-- Fixed ids so this script is safe to re-run (ON CONFLICT DO NOTHING) and easy to eyeball.
-- alert 1: queued, critical, brute force with a full Tier-2 brief + feedback
INSERT INTO alerts (id, source, external_id, incident_id, raw, normalized, ground_truth_label, ingested_at)
VALUES (
  '11111111-1111-4111-8111-111111111111',
  'wazuh',
  'wazuh-evt-9001',
  'INC-1001',
  '{"rule":{"id":"5712","description":"SSHD brute force trying to get access","level":10}}',
  '{
    "alert": {"source": "wazuh", "rule_id": "5712", "rule_description": "SSHD brute force trying to get access", "rule_level": 10, "mitre_hint": ["T1110"], "timestamp_utc": "2026-09-20T03:12:44Z"},
    "entities": {"src_ip": "203.0.113.7", "user": "svc-backup", "host": "db-prod-02"},
    "derived": {"failed_auth_10m": 212, "successful_auth_after_failures": true, "off_hours": true, "src_ip_first_seen_days": 0, "src_ip_reputation": "malicious", "host_criticality": "crown_jewel", "rule_historical_fp_rate": 0.62, "similar_alerts_24h": 3},
    "untrusted_evidence": {"raw_log_excerpt": "Accepted password for svc-backup from 203.0.113.7 port 51022"}
  }'::jsonb,
  'true_positive',
  now() - interval '2 hours'
)
ON CONFLICT (source, external_id) WHERE external_id IS NOT NULL DO NOTHING;

-- alert 2: queued, high severity, needs more context, no brief yet
INSERT INTO alerts (id, source, external_id, incident_id, raw, normalized, ground_truth_label, ingested_at)
VALUES (
  '22222222-2222-4222-8222-222222222222',
  'guide_replay',
  'guide-4471',
  'INC-1002',
  '{"rule":{"id":"3010","description":"Suspicious PowerShell encoded command"}}',
  '{
    "alert": {"source": "guide_replay", "rule_id": "3010", "rule_description": "Suspicious PowerShell encoded command", "rule_level": 8, "mitre_hint": ["T1059.001"], "timestamp_utc": "2026-09-21T14:02:10Z"},
    "entities": {"src_ip": "10.0.4.22", "user": "j.alvarez", "host": "ws-fin-014"},
    "derived": {"failed_auth_10m": 0, "successful_auth_after_failures": false, "off_hours": false, "src_ip_first_seen_days": 41, "src_ip_reputation": "unknown", "host_criticality": "standard", "rule_historical_fp_rate": 0.35, "similar_alerts_24h": 1},
    "untrusted_evidence": {"raw_log_excerpt": "powershell.exe -enc SQBFAFgA..."}
  }'::jsonb,
  'benign_positive',
  now() - interval '5 hours'
)
ON CONFLICT (source, external_id) WHERE external_id IS NOT NULL DO NOTHING;

-- alert 3: queued, low severity, older, no decisions/feedback yet (sparse row for edge-case testing)
INSERT INTO alerts (id, source, external_id, incident_id, raw, normalized, ground_truth_label, ingested_at)
VALUES (
  '33333333-3333-4333-8333-333333333333',
  'cicids_replay',
  'cicids-flow-88213',
  'INC-1003',
  '{"flow":{"proto":"tcp","dst_port":445}}',
  '{
    "alert": {"source": "cicids_replay", "rule_id": "smb-anomaly-1", "rule_description": "Anomalous SMB flow volume", "rule_level": 4, "mitre_hint": ["T1021.002"], "timestamp_utc": "2026-09-22T09:45:00Z"},
    "entities": {"src_ip": "10.0.9.5", "user": null, "host": "fileserver-03"},
    "derived": {"failed_auth_10m": 0, "successful_auth_after_failures": false, "off_hours": false, "src_ip_first_seen_days": 300, "src_ip_reputation": "clean", "host_criticality": "standard", "rule_historical_fp_rate": 0.81, "similar_alerts_24h": 9},
    "untrusted_evidence": {"raw_log_excerpt": "SMB2 session setup burst from 10.0.9.5"}
  }'::jsonb,
  'false_positive',
  now() - interval '1 day'
)
ON CONFLICT (source, external_id) WHERE external_id IS NOT NULL DO NOTHING;

-- alert 4: auto_escalated (not in the queue) so the queue screen isn't the only path exercised
INSERT INTO alerts (id, source, external_id, incident_id, raw, normalized, ground_truth_label, ingested_at)
VALUES (
  '44444444-4444-4444-8444-444444444444',
  'wazuh',
  'wazuh-evt-9044',
  'INC-1004',
  '{"rule":{"id":"5501","description":"Ransomware indicator: mass file rename"}}',
  '{
    "alert": {"source": "wazuh", "rule_id": "5501", "rule_description": "Ransomware indicator: mass file rename", "rule_level": 15, "mitre_hint": ["T1486"], "timestamp_utc": "2026-09-23T02:00:00Z"},
    "entities": {"src_ip": "203.0.113.90", "user": "svc-backup", "host": "db-prod-01"},
    "derived": {"failed_auth_10m": 0, "successful_auth_after_failures": false, "off_hours": true, "src_ip_first_seen_days": 0, "src_ip_reputation": "malicious", "host_criticality": "crown_jewel", "rule_historical_fp_rate": 0.02, "similar_alerts_24h": 1},
    "untrusted_evidence": {"raw_log_excerpt": "12,400 files renamed to *.locked in /data/prod"}
  }'::jsonb,
  'true_positive',
  now() - interval '30 minutes'
)
ON CONFLICT (source, external_id) WHERE external_id IS NOT NULL DO NOTHING;

-- jev_decisions
INSERT INTO jev_decisions (alert_id, triage_verdict, is_false_positive_prob, severity, attack_category, needs_more_context_prob, business_impact_if_true, confidence_margin, raw_response, latency_ms, created_at)
VALUES
  ('11111111-1111-4111-8111-111111111111', 'true_positive', 0.04, 'critical', 'credential_access', 0.71, 'high', 0.62, '{"triage_verdict": "true_positive", "severity": "critical", "probabilities": {"true_positive": 0.81, "benign_positive": 0.11, "false_positive": 0.05, "other": 0.03}}'::jsonb, 340, now() - interval '2 hours' + interval '2 seconds'),
  ('22222222-2222-4222-8222-222222222222', 'true_positive', 0.22, 'high', 'execution', 0.88, 'medium', 0.18, '{"triage_verdict": "true_positive", "severity": "high", "probabilities": {"true_positive": 0.47, "benign_positive": 0.35, "false_positive": 0.12, "other": 0.06}}'::jsonb, 410, now() - interval '5 hours' + interval '2 seconds'),
  ('33333333-3333-4333-8333-333333333333', 'false_positive', 0.93, 'low', 'discovery', 0.05, 'low', 0.81, '{"triage_verdict": "false_positive", "severity": "low", "probabilities": {"false_positive": 0.91, "benign_positive": 0.06, "true_positive": 0.02, "other": 0.01}}'::jsonb, 298, now() - interval '1 day' + interval '2 seconds'),
  ('44444444-4444-4444-8444-444444444444', 'true_positive', 0.01, 'critical', 'impact', 0.15, 'high', 0.94, '{"triage_verdict": "true_positive", "severity": "critical", "probabilities": {"true_positive": 0.97, "benign_positive": 0.02, "false_positive": 0.005, "other": 0.005}}'::jsonb, 275, now() - interval '30 minutes' + interval '2 seconds');

-- policy_outcomes (latest one per alert is what the queue/detail screens read)
INSERT INTO policy_outcomes (alert_id, action, rule_version, reason, shadow_mode, created_at)
VALUES
  ('11111111-1111-4111-8111-111111111111', 'queued', 'v1', 'crown_jewel host exempts from auto-close despite low FP prob', false, now() - interval '2 hours' + interval '5 seconds'),
  ('22222222-2222-4222-8222-222222222222', 'queued', 'v1', 'needs_more_context_prob 0.88 >= escalation threshold; default queue_with_tier2_brief', false, now() - interval '5 hours' + interval '5 seconds'),
  ('33333333-3333-4333-8333-333333333333', 'queued', 'v1', 'confidence 0.81 below auto_close threshold 0.90', false, now() - interval '1 day' + interval '5 seconds'),
  ('44444444-4444-4444-8444-444444444444', 'auto_escalate', 'v1', 'verdict true_positive, confidence 0.94 >= 0.85, severity critical >= 2.5', false, now() - interval '30 minutes' + interval '5 seconds');

-- briefs (only alert 1 has a full brief)
INSERT INTO briefs (alert_id, provider_model, summary, attack_chain, mitre_techniques, recommended_actions, open_questions, cited_log_ids, tokens_in, tokens_out, cost_usd, created_at)
VALUES (
  '11111111-1111-4111-8111-111111111111',
  'luna',
  'A distributed brute-force campaign against the SSH service on db-prod-02 succeeded after 212 failed attempts within 10 minutes, authenticating as the service account svc-backup from a known-malicious source IP outside business hours. Given the crown-jewel host criticality, this should be treated as a likely true positive pending analyst confirmation.',
  '[
    {"step": 1, "description": "212 failed SSH auth attempts from 203.0.113.7 against svc-backup", "log_line_id": "log-77021"},
    {"step": 2, "description": "Successful authentication immediately following the failure burst", "log_line_id": "log-77022"},
    {"step": 3, "description": "First-seen source IP with known-malicious reputation, off-hours", "log_line_id": "log-77023"}
  ]'::jsonb,
  '["T1110", "T1078"]'::jsonb,
  '["Disable svc-backup pending investigation", "Block 203.0.113.7 at the perimeter firewall", "Force credential rotation for svc-backup", "Review db-prod-02 for lateral movement"]'::jsonb,
  '["Was svc-backup used interactively elsewhere in the same window?", "Is MFA enforced for service accounts on this host?"]'::jsonb,
  '["log-77021", "log-77022", "log-77023"]'::jsonb,
  18400,
  612,
  0.004840,
  now() - interval '2 hours' + interval '20 seconds'
);

-- feedback (alert 1 has analyst feedback already; others do not, to exercise the empty state)
INSERT INTO feedback (alert_id, analyst_verdict, correct, notes, created_at)
VALUES (
  '11111111-1111-4111-8111-111111111111',
  'true_positive',
  true,
  'Confirmed with the infra team, svc-backup credential was compromised via a leaked deploy key.',
  now() - interval '1 hour'
);

-- costs: jev + tier2 rows spanning today and yesterday so the cost tile has something to aggregate
INSERT INTO costs (alert_id, call_type, provider, model, tokens_in, tokens_out, cost_usd, created_at)
VALUES
  ('11111111-1111-4111-8111-111111111111', 'jev', 'typesafe', 'jev-latest', 640, 120, 0.000210, now() - interval '2 hours'),
  ('22222222-2222-4222-8222-222222222222', 'jev', 'typesafe', 'jev-latest', 588, 110, 0.000195, now() - interval '5 hours'),
  ('33333333-3333-4333-8333-333333333333', 'jev', 'typesafe', 'jev-latest', 512, 98, 0.000171, now() - interval '1 day'),
  ('44444444-4444-4444-8444-444444444444', 'jev', 'typesafe', 'jev-latest', 601, 115, 0.000201, now() - interval '30 minutes'),
  ('11111111-1111-4111-8111-111111111111', 'tier2', 'openai', 'gpt-6-luna', 18400, 612, 0.004840, now() - interval '2 hours' + interval '20 seconds'),
  (NULL, 'jev', 'typesafe', 'jev-latest', 550, 105, 0.000188, now() - interval '1 day' - interval '3 hours'),
  (NULL, 'tier2', 'openai', 'gpt-6-sol', 22100, 780, 0.052400, now() - interval '1 day' - interval '2 hours');

COMMIT;
