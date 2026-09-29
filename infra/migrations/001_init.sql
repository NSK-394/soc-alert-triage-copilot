-- SOC Alert Triage Copilot — initial schema (docs/architecture.md §4)
-- Run automatically by the postgres image's docker-entrypoint-initdb.d on first boot.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source          TEXT NOT NULL,              -- 'wazuh' | 'guide_replay' | 'cicids_replay' | ...
    external_id     TEXT,                        -- source-provided id, for idempotent replay
    incident_id     TEXT,                        -- groups related alerts; used for GUIDE incident-level splits
    raw             JSONB NOT NULL,               -- untouched source payload
    normalized      JSONB NOT NULL DEFAULT '{}',  -- feature-builder state object (docs/architecture.md §4); populated once the Phase C pipeline wires feature-builder in, empty at raw ingest
    ground_truth_label TEXT,                      -- GUIDE's TP/BP/FP label, only present for replayed labeled data
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_alerts_incident_id ON alerts (incident_id);
CREATE INDEX idx_alerts_source ON alerts (source);
CREATE UNIQUE INDEX uq_alerts_source_external_id ON alerts (source, external_id) WHERE external_id IS NOT NULL;

CREATE TABLE jev_decisions (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id                    UUID NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    triage_verdict               TEXT NOT NULL,     -- true_positive | benign_positive | false_positive | other
    is_false_positive_prob      NUMERIC(5, 4),
    severity                    TEXT NOT NULL,     -- informational | low | high | critical
    attack_category             TEXT,
    needs_more_context_prob     NUMERIC(5, 4),
    business_impact_if_true     TEXT,
    confidence_margin           NUMERIC(5, 4),      -- our own margin/entropy computation, not Jev's raw confidence
    raw_response                JSONB NOT NULL,
    latency_ms                  INTEGER,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_jev_decisions_alert_id ON jev_decisions (alert_id);

CREATE TABLE policy_outcomes (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id      UUID NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    action        TEXT NOT NULL CHECK (action IN ('auto_close', 'auto_escalate', 'queued')),
    rule_version  TEXT NOT NULL,
    reason        TEXT,                             -- which rule/threshold fired
    shadow_mode   BOOLEAN NOT NULL DEFAULT false,    -- true while evaluating without acting
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_policy_outcomes_alert_id ON policy_outcomes (alert_id);

CREATE TABLE briefs (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id              UUID NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    provider_model        TEXT NOT NULL,             -- luna | sol | astra
    summary               TEXT NOT NULL,
    attack_chain          JSONB NOT NULL DEFAULT '[]',
    mitre_techniques      JSONB NOT NULL DEFAULT '[]',
    recommended_actions   JSONB NOT NULL DEFAULT '[]',
    open_questions        JSONB NOT NULL DEFAULT '[]',
    cited_log_ids         JSONB NOT NULL DEFAULT '[]',
    tokens_in             INTEGER NOT NULL,
    tokens_out            INTEGER NOT NULL,
    cost_usd              NUMERIC(10, 6) NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_briefs_alert_id ON briefs (alert_id);

CREATE TABLE feedback (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id         UUID NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    analyst_verdict  TEXT NOT NULL,
    correct          BOOLEAN NOT NULL,               -- was the Jev/policy/brief verdict correct
    notes            TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_feedback_alert_id ON feedback (alert_id);

CREATE TABLE costs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id    UUID REFERENCES alerts (id) ON DELETE SET NULL,
    call_type   TEXT NOT NULL CHECK (call_type IN ('jev', 'tier2')),
    provider    TEXT NOT NULL,
    model       TEXT NOT NULL,
    tokens_in   INTEGER NOT NULL,
    tokens_out  INTEGER NOT NULL,
    cost_usd    NUMERIC(10, 6) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_costs_created_at ON costs (created_at);
CREATE INDEX idx_costs_alert_id ON costs (alert_id);
