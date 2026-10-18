export type Decision = 'allow' | 'review' | 'block';
export interface EventBase {
  schema_version: '1.0'; trace_id: string; event_id: string; timestamp: string; call_id: string;
}
export type TraceEvent = EventBase & (
  { type: 'tool_call'; tool: string; arguments: Record<string, unknown> } |
  { type: 'tool_result'; status: 'ok' | 'error'; output: unknown }
);
export interface Finding {
  rule_id: string; rule_version: string; severity: string; event_ids: string[];
  field: string; evidence: string; message: string;
  title?: string; limitations?: string | string[];
  evidence_items?: { field: string; value: unknown; truncated: boolean }[];
}
export interface PolicyDecision {
  event_id: string; call_id: string; decision: Decision;
  matches: { source: string; decision: Decision }[];
  coverage: string; coverage_reason: string;
  intervention_sources?: string[]; coverage_reasons?: string[];
  recorded_continuation_after_block?: boolean; blocked_by_event_id?: string | null;
}
export interface PolicyRun {
  policy: { policy_id: string; version: string };
  decisions: PolicyDecision[];
  counts: Record<Decision, number>;
  interventions: { rule_triggered: number; unknown_action: number };
}
export interface Analysis {
  sanitization: { version: '1.0'; redactions: number; notice: string; reference_semantics: string };
  reports: { format_version: '1.0'; json: string; markdown: string; report_sha256: string };
  trace_id: string; source_sha256: string;
  policy: { policy_id: string; version: string };
  events: TraceEvent[]; findings: Finding[]; decisions: PolicyDecision[];
  warnings: { code: string; event_ids: string[] }[]; disclaimer: string;
  comparison?: { baseline: PolicyRun; strict: PolicyRun; differences: { event_id: string; baseline: Decision; strict: Decision; reason: string }[] };
  unknown_coverage?: { event_id: string; reasons: string[] }[];
  rules?: Record<string, unknown>[]; engine_config?: Record<string, unknown>;
}
