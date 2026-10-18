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
}
export interface PolicyDecision {
  event_id: string; call_id: string; decision: Decision;
  matches: { source: string; decision: Decision }[];
  coverage: string; coverage_reason: string;
}
export interface Analysis {
  trace_id: string; source_sha256: string;
  policy: { policy_id: string; version: string };
  events: TraceEvent[]; findings: Finding[]; decisions: PolicyDecision[];
  warnings: { code: string; event_ids: string[] }[]; disclaimer: string;
}
