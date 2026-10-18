import type { Analysis } from './types';
export const MAX_BYTES = 5 * 1024 * 1024;

export async function analyzeTrace(raw: string, policy: string): Promise<Analysis> {
  const response = await fetch(`/api/analyze?policy=${encodeURIComponent(policy)}`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-ndjson' }, body: raw,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const error = body?.error;
    throw new Error(error ? `Import rejected: ${error.code}${error.line ? ` at line ${error.line}` : ''}.` : `Analysis failed (HTTP ${response.status}).`);
  }
  return response.json();
}

export async function loadSample(name: 'benign' | 'risky' | 'forensic'): Promise<string> {
  const response = await fetch(`/api/samples/${name}`);
  if (!response.ok) throw new Error('Could not load sample. Is the backend running?');
  return (await response.json()).jsonl;
}
