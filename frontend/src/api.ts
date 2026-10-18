import type { Analysis } from './types';
export const MAX_BYTES = 5 * 1024 * 1024;
export class SafeError extends Error {}
const KNOWN_CODES = new Set(['input_too_large', 'invalid_utf8', 'line_too_large', 'event_limit', 'nesting_limit', 'invalid_event', 'duplicate_event_id', 'mixed_trace_ids', 'duplicate_call_id', 'duplicate_result', 'empty_trace', 'invalid_policy', 'invalid_request', 'invalid_engine_config', 'config_too_large']);
export function safeMessage(error: unknown, fallback: string): string {
  return error instanceof SafeError ? error.message : fallback;
}

export async function analyzeTrace(raw: string, policy: string): Promise<Analysis> {
  const response = await fetch(`/api/analyze?policy=${encodeURIComponent(policy)}`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-ndjson' }, body: raw,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const error = body?.error;
    const line = Number.isInteger(error?.line) && error.line > 0 && error.line <= MAX_BYTES ? ` at line ${error.line}` : '';
    throw new SafeError(KNOWN_CODES.has(error?.code) ? `Import rejected: ${error.code}${line}.` : `Analysis failed (HTTP ${response.status}).`);
  }
  const data = await response.json();
  if (data?.sanitization?.version !== '1.0') {
    throw new SafeError('Backend response is not sanitized; restart or update the backend.');
  }
  return data;
}

export async function loadSample(name: 'benign' | 'risky' | 'forensic'): Promise<string> {
  const response = await fetch(`/api/samples/${name}`);
  if (!response.ok) throw new SafeError('Could not load sample. Is the backend running?');
  const data = await response.json();
  if (typeof data?.jsonl !== 'string') throw new SafeError('Could not load sample. Is the backend running?');
  return data.jsonl;
}
