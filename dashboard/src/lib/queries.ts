import { sql } from './db';
import type {
  AlertRow,
  BriefRow,
  CostSummaryRow,
  FeedbackRow,
  JevDecisionRow,
  PolicyOutcomeRow,
  QueueRow,
  Tier2Model,
} from './types';

/**
 * Queue screen: alerts whose *latest* policy_outcomes row has action = 'queued',
 * joined to each alert's latest jev_decisions row, sorted by severity (critical first)
 * then most-recently-ingested first. All parameterized (none needed here, but kept
 * consistent with the rest of the module).
 */
export async function getQueue(): Promise<QueueRow[]> {
  const rows = await sql<QueueRow[]>`
    WITH latest_policy AS (
      SELECT DISTINCT ON (alert_id) *
      FROM policy_outcomes
      ORDER BY alert_id, created_at DESC
    ),
    latest_decision AS (
      SELECT DISTINCT ON (alert_id) *
      FROM jev_decisions
      ORDER BY alert_id, created_at DESC
    )
    SELECT
      a.id,
      a.source,
      a.external_id,
      a.incident_id,
      a.ingested_at,
      d.triage_verdict,
      d.severity,
      d.confidence_margin,
      d.attack_category,
      p.action,
      p.reason
    FROM alerts a
    JOIN latest_policy p ON p.alert_id = a.id
    LEFT JOIN latest_decision d ON d.alert_id = a.id
    WHERE p.action = 'queued'
    ORDER BY
      CASE d.severity
        WHEN 'critical' THEN 4
        WHEN 'high' THEN 3
        WHEN 'low' THEN 2
        WHEN 'informational' THEN 1
        ELSE 0
      END DESC,
      a.ingested_at DESC
  `;
  return rows;
}

export async function getAlert(alertId: string): Promise<AlertRow | null> {
  const rows = await sql<AlertRow[]>`
    SELECT id, source, external_id, incident_id, raw, normalized, ground_truth_label, ingested_at
    FROM alerts
    WHERE id = ${alertId}
    LIMIT 1
  `;
  return rows[0] ?? null;
}

export async function getLatestJevDecision(alertId: string): Promise<JevDecisionRow | null> {
  const rows = await sql<JevDecisionRow[]>`
    SELECT *
    FROM jev_decisions
    WHERE alert_id = ${alertId}
    ORDER BY created_at DESC
    LIMIT 1
  `;
  return rows[0] ?? null;
}

export async function getLatestPolicyOutcome(alertId: string): Promise<PolicyOutcomeRow | null> {
  const rows = await sql<PolicyOutcomeRow[]>`
    SELECT *
    FROM policy_outcomes
    WHERE alert_id = ${alertId}
    ORDER BY created_at DESC
    LIMIT 1
  `;
  return rows[0] ?? null;
}

export async function getLatestBrief(alertId: string): Promise<BriefRow | null> {
  const rows = await sql<BriefRow[]>`
    SELECT *
    FROM briefs
    WHERE alert_id = ${alertId}
    ORDER BY created_at DESC
    LIMIT 1
  `;
  return rows[0] ?? null;
}

export async function getFeedbackForAlert(alertId: string): Promise<FeedbackRow[]> {
  const rows = await sql<FeedbackRow[]>`
    SELECT *
    FROM feedback
    WHERE alert_id = ${alertId}
    ORDER BY created_at DESC
  `;
  return rows;
}

/** Cost tile: total spend per call_type, plus the alert count needed to derive cost-per-1000. */
export async function getCostSummary(): Promise<{
  perCallType: CostSummaryRow[];
  totalAlerts: number;
}> {
  const perCallType = await sql<CostSummaryRow[]>`
    SELECT
      c.call_type,
      COALESCE(SUM(c.cost_usd), 0) AS total_cost_usd,
      (SELECT COUNT(*) FROM alerts) AS total_alerts
    FROM costs c
    GROUP BY c.call_type
  `;
  const totalAlertsRows = await sql<{ count: string }[]>`SELECT COUNT(*) FROM alerts`;
  return {
    perCallType,
    totalAlerts: parseInt(totalAlertsRows[0]?.count ?? '0', 10),
  };
}

export async function insertFeedback(params: {
  alertId: string;
  analystVerdict: string;
  correct: boolean;
  notes?: string | null;
}): Promise<void> {
  await sql`
    INSERT INTO feedback (alert_id, analyst_verdict, correct, notes)
    VALUES (${params.alertId}, ${params.analystVerdict}, ${params.correct}, ${params.notes ?? null})
  `;
}

export async function getTier2ModelSetting(): Promise<Tier2Model | null> {
  const rows = await sql<{ value: string }[]>`
    SELECT value FROM settings WHERE key = 'tier2_model' LIMIT 1
  `;
  return (rows[0]?.value as Tier2Model | undefined) ?? null;
}

export async function setTier2ModelSetting(model: Tier2Model): Promise<void> {
  await sql`
    INSERT INTO settings (key, value, updated_at)
    VALUES ('tier2_model', ${model}, now())
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
  `;
}
