export type Severity = 'informational' | 'low' | 'high' | 'critical' | string;
export type PolicyAction = 'auto_close' | 'auto_escalate' | 'queued';
export type CallType = 'jev' | 'tier2';

export interface QueueRow {
  id: string;
  source: string;
  external_id: string | null;
  incident_id: string | null;
  ingested_at: string;
  triage_verdict: string | null;
  severity: Severity | null;
  confidence_margin: string | null; // numeric comes back as string from postgres.js
  attack_category: string | null;
  action: PolicyAction;
  reason: string | null;
}

export interface AlertRow {
  id: string;
  source: string;
  external_id: string | null;
  incident_id: string | null;
  raw: unknown;
  normalized: unknown;
  ground_truth_label: string | null;
  ingested_at: string;
}

export interface JevDecisionRow {
  id: string;
  alert_id: string;
  triage_verdict: string;
  is_false_positive_prob: string | null;
  severity: Severity;
  attack_category: string | null;
  needs_more_context_prob: string | null;
  business_impact_if_true: string | null;
  confidence_margin: string | null;
  raw_response: unknown;
  latency_ms: number | null;
  created_at: string;
}

export interface PolicyOutcomeRow {
  id: string;
  alert_id: string;
  action: PolicyAction;
  rule_version: string;
  reason: string | null;
  shadow_mode: boolean;
  created_at: string;
}

export interface BriefRow {
  id: string;
  alert_id: string;
  provider_model: string;
  summary: string;
  attack_chain: unknown;
  mitre_techniques: unknown;
  recommended_actions: unknown;
  open_questions: unknown;
  cited_log_ids: unknown;
  tokens_in: number;
  tokens_out: number;
  cost_usd: string;
  created_at: string;
}

export interface FeedbackRow {
  id: string;
  alert_id: string;
  analyst_verdict: string;
  correct: boolean;
  notes: string | null;
  created_at: string;
}

export interface CostSummaryRow {
  call_type: CallType;
  total_cost_usd: string;
  total_alerts: string;
}

export const TIER2_MODELS = ['luna', 'sol', 'astra'] as const;
export type Tier2Model = (typeof TIER2_MODELS)[number];
