import { render, screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from '../src/App';
import { analyzeTrace } from '../src/api';
import type { Analysis } from '../src/types';

const data: Analysis = {
  trace_id: 'synthetic-risky', source_sha256: 'abc123', policy: { policy_id: 'baseline', version: '2.0' },
  events: [{ schema_version: '1.0', trace_id: 'synthetic-risky', event_id: 'e1', timestamp: '2026-10-18T10:00:00Z', call_id: 'c1', type: 'tool_call', tool: 'process.exec', arguments: { argv: ['sudo', 'id'], cwd: '/workspace', shell: false } },
    { schema_version: '1.0', trace_id: 'synthetic-risky', event_id: 'e2', timestamp: '2026-10-18T10:00:01Z', call_id: 'c1', type: 'tool_result', status: 'ok', output: '<script>window.hacked=true</script>' }],
  findings: [{ rule_id: 'R002', rule_version: '2.0', severity: 'high', event_ids: ['e1'], field: 'arguments.argv[0]', evidence: 'sudo', message: 'Direct privileged executable invocation.', title: 'Direct privilege elevation', limitations: ['Recorded executable only'], evidence_items: [{ field: 'arguments.argv', value: '<img src=x onerror=alert(1)>', truncated: true }] }],
  decisions: [{ event_id: 'e1', call_id: 'c1', decision: 'review', matches: [{ source: 'rule:R002', decision: 'review' }], coverage: 'limited', coverage_reason: 'Six bounded checks.', coverage_reasons: ['Six bounded checks.'], intervention_sources: ['rule:R002', 'unknown_action'], recorded_continuation_after_block: false, blocked_by_event_id: null }],
  unknown_coverage: [{ event_id: 'e1', reasons: ['Unsupported argument shape'] }], rules: [{ rule_id: 'R002', version: '2.0' }], engine_config: {},
  warnings: [], disclaimer: 'Recorded actions only.',
};
data.comparison = {
  baseline: { policy: data.policy, decisions: data.decisions, counts: { allow: 0, review: 1, block: 0 }, interventions: { rule_triggered: 1, unknown_action: 1 } },
  strict: { policy: { policy_id: 'strict', version: '2.0' }, decisions: [
    { ...data.decisions[0], decision: 'block', matches: [{ source: 'rule:R002', decision: 'block' }] },
    { ...data.decisions[0], event_id: 'e2', decision: 'review', intervention_sources: ['unknown_action'], recorded_continuation_after_block: true, blocked_by_event_id: 'e1' },
  ], counts: { allow: 0, review: 1, block: 1 }, interventions: { rule_triggered: 1, unknown_action: 2 } },
  differences: [{ event_id: 'e1', baseline: 'review', strict: 'block', reason: 'Strict blocks all rule-backed matches.' }],
};
function mockFetch(response = data) {
  const mock = vi.fn(async (url: string) => {
    if (url.includes('/samples/')) return new Response(JSON.stringify({ synthetic: true, jsonl: '{"synthetic":true}' }));
    return new Response(JSON.stringify(response));
  });
  vi.stubGlobal('fetch', mock);
  return mock;
}
afterEach(() => vi.unstubAllGlobals());

describe('import-to-analysis workbench', () => {
  it('shows empty state and honest replay disclaimer', () => {
    render(<App />);
    expect(screen.getByText('Your investigation starts here')).toBeVisible();
    expect(screen.getByText(/Does not execute actions or predict/)).toBeVisible();
  });
  it('loads a sample, shows evidence, inspects results and switches policy', async () => {
    const mock = mockFetch(); const user = userEvent.setup(); render(<App />);
    await user.click(screen.getByRole('button', { name: 'Risky sample' }));
    expect(await screen.findByRole('heading', { name: 'synthetic-risky' })).toBeVisible();
    expect(screen.getByRole('heading', { name: /R002 v2.0 · Direct privilege elevation/ })).toBeVisible();
    expect(screen.getByText('rule:R002 → review')).toBeVisible();
    const timeline = screen.getByRole('region', { name: 'Event timeline' });
    await user.click(within(timeline).getByRole('button', { name: /Result/ }));
    expect(screen.getByLabelText('Recorded event payload')).toHaveTextContent('<script>window.hacked=true</script>');
    expect(document.querySelector('script')).toBeNull();
    await user.click(within(screen.getByRole('region', { name: 'Findings & evidence' })).getByRole('button', { name: 'e1' }));
    expect(screen.getByLabelText('Recorded event payload')).toHaveTextContent('sudo');
    await user.selectOptions(screen.getByLabelText('Replay policy'), 'strict');
    await waitFor(() => expect(screen.getByText('Policy: strict v2.0')).toBeVisible());
    expect(mock).toHaveBeenCalledTimes(2);
    expect(mock).toHaveBeenLastCalledWith('/api/analyze?policy=baseline', expect.objectContaining({ method: 'POST', body: '{"synthetic":true}' }));
  });
  it('imports a file through the real API client', async () => {
    const mock = mockFetch(); const user = userEvent.setup(); render(<App />);
    const file = new File(['{"schema_version":"1.0"}'], 'trace.jsonl', { type: 'application/x-ndjson' });
    Object.defineProperty(file, 'arrayBuffer', { value: async () => new TextEncoder().encode('{"schema_version":"1.0"}').buffer });
    await user.upload(screen.getByLabelText('Import JSONL'), file);
    expect(await screen.findByText('trace.jsonl')).toBeVisible();
    expect(mock).toHaveBeenCalledWith('/api/analyze?policy=baseline', expect.objectContaining({ body: '{"schema_version":"1.0"}' }));
  });
  it('shows a bounded line-numbered error and no stale analysis', async () => {
    const mock = mockFetch(); render(<App />);
    await userEvent.click(screen.getByRole('button', { name: 'Risky sample' }));
    expect(await screen.findByRole('region', { name: 'Event timeline' })).toBeVisible();
    mock.mockImplementation(async (url: string) => url.includes('samples')
      ? new Response(JSON.stringify({ jsonl: 'invalid' }))
      : new Response(JSON.stringify({ error: { code: 'invalid_event', line: 2 } }), { status: 422 }));
    await userEvent.click(screen.getByRole('button', { name: 'Benign sample' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('invalid_event at line 2');
    expect(screen.queryByRole('region', { name: 'Event timeline' })).not.toBeInTheDocument();
  });
  it('rejects oversized files without a request', async () => {
    const mock = mockFetch(); render(<App />);
    const file = new File(['x'], 'large.jsonl'); Object.defineProperty(file, 'size', { value: 5 * 1024 * 1024 + 1 });
    await userEvent.upload(screen.getByLabelText('Import JSONL'), file);
    expect(await screen.findByRole('alert')).toHaveTextContent('exceeds 5 MiB');
    expect(mock).not.toHaveBeenCalled();
  });
  it('reports network failures', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network unavailable')));
    render(<App />); await userEvent.click(screen.getByRole('button', { name: 'Risky sample' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Network unavailable');
  });
  it('formats non-JSON server errors safely', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('not JSON', { status: 500 })));
    await expect(analyzeTrace('{}', 'baseline')).rejects.toThrow('HTTP 500');
  });
  it('shows independent intervention counts, same-trace differences and separate unknown coverage', async () => {
    mockFetch(); render(<App />); await userEvent.click(screen.getByRole('button', { name: 'Six-rule sample' }));
    const baseline = await screen.findByRole('region', { name: 'baseline summary' });
    const strict = screen.getByRole('region', { name: 'strict summary' });
    expect(baseline).toHaveTextContent('Allow0Review1Block0Rule-triggered interventions1Unknown-action interventions1');
    expect(strict).toHaveTextContent('Allow0Review1Block1Rule-triggered interventions1Unknown-action interventions2');
    expect(within(baseline).getByText(/categories can overlap/)).toBeVisible();
    expect(screen.getByText(/abc123/)).toBeVisible();
    const differences = screen.getByRole('region', { name: 'Per-action policy differences' });
    expect(differences).toHaveTextContent('Why change: Strict blocks all rule-backed matches.');
    await userEvent.click(within(differences).getByRole('button', { name: 'e1' }));
    await waitFor(() => expect(screen.getByRole('button', { name: /01 process.exec/ })).toHaveFocus());
    expect(screen.getByRole('region', { name: 'Unknown analysis coverage' })).toHaveTextContent('Unsupported argument shape');
    expect(screen.getByRole('region', { name: 'Policy interventions' })).toHaveTextContent('rule:R002, unknown_action');
    expect(screen.getByText('<img src=x onerror=alert(1)>', { exact: false })).toBeVisible();
    expect(document.querySelector('img')).toBeNull();
    expect(screen.getByText('Evidence truncated by engine.')).toBeVisible();
  });
  it('labels recorded continuation without predicting agent behavior', async () => {
    const fixture = structuredClone(data);
    fixture.events[1] = { ...fixture.events[1], type: 'tool_call', tool: 'custom.recorded', arguments: { action: 'continued in original recording' } };
    mockFetch(fixture); render(<App />); const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Risky sample' }));
    await screen.findByRole('region', { name: 'Event timeline' });
    await user.selectOptions(screen.getByLabelText('Replay policy'), 'strict');
    await user.click(within(screen.getByRole('region', { name: 'Event timeline' })).getByRole('button', { name: /custom.recorded/ }));
    expect(screen.getByRole('region', { name: 'Event evidence' })).toHaveTextContent('Recorded continuation after hypothetical block e1 — not a prediction');
  });
  it('handles no-change traces without calling no findings safe', async () => {
    const fixture = structuredClone(data); fixture.findings = []; fixture.unknown_coverage = []; fixture.comparison!.differences = [];
    mockFetch(fixture); render(<App />); await userEvent.click(screen.getByRole('button', { name: 'Benign sample' }));
    expect(await screen.findByText('No policy changes for this trace.')).toBeVisible();
    expect(screen.getByText(/No rule-backed findings. This is not proof of safety/)).toBeVisible();
    expect(screen.getByText('No unknown analysis coverage reported.')).toBeVisible();
  });
  it('bounds payload excerpts and paginates large collections with event navigation', async () => {
    const fixture = structuredClone(data);
    fixture.events[1] = { ...fixture.events[1], type: 'tool_result', status: 'ok', output: 'x'.repeat(9000) + 'PAYLOAD_END' };
    fixture.findings = Array.from({ length: 101 }, () => fixture.findings[0]);
    fixture.unknown_coverage = Array.from({ length: 101 }, (_, i) => ({ event_id: 'e1', reasons: [`Gap ${i}`] }));
    fixture.comparison!.differences = Array.from({ length: 101 }, () => fixture.comparison!.differences[0]);
    fixture.comparison!.baseline.decisions = Array.from({ length: 101 }, () => fixture.decisions[0]);
    mockFetch(fixture); render(<App />); const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Risky sample' }));
    const timeline = await screen.findByRole('region', { name: 'Event timeline' });
    await user.click(within(timeline).getByRole('button', { name: /Result/ }));
    expect(screen.getByLabelText('Recorded event payload')).toHaveTextContent('Truncated: showing first 8192 code units');
    expect(screen.getByLabelText('Recorded event payload')).not.toHaveTextContent('PAYLOAD_END');
    for (const label of ['Findings', 'Unknown coverage', 'Differences', 'Interventions']) {
      const pages = screen.getByRole('navigation', { name: `${label} pages` });
      await user.click(within(pages).getByRole('button', { name: 'Next' }));
      expect(pages).toHaveTextContent('Page 2 / 2');
      expect(within(pages).getByRole('button', { name: 'Next' })).toBeDisabled();
    }
    expect(screen.getByText('Gap 100')).toBeVisible();
  });
  it('rejects oversized sample content through the real client flow', async () => {
    const mock = vi.fn(async () => new Response(JSON.stringify({ jsonl: 'x'.repeat(5 * 1024 * 1024 + 1) })));
    vi.stubGlobal('fetch', mock); render(<App />); await userEvent.click(screen.getByRole('button', { name: 'Risky sample' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('exceeds 5 MiB');
    expect(mock).toHaveBeenCalledTimes(1);
  });
  it('renders all six rule titles with review versus block counts from one forensic analysis', async () => {
    const fixture = structuredClone(data);
    fixture.events = Array.from({ length: 6 }, (_, i) => ({ ...data.events[0], event_id: `rule-event-${i}`, call_id: `rule-call-${i}` }));
    fixture.findings = fixture.events.map((event, i) => ({ ...data.findings[0], rule_id: `R00${i + 1}`, title: `Backend rule title ${i + 1}`, event_ids: [event.event_id] }));
    fixture.comparison!.baseline.decisions = fixture.events.map((event, i) => ({ ...data.decisions[0], event_id: event.event_id, call_id: event.call_id, intervention_sources: [`rule:R00${i + 1}`], matches: [{ source: `rule:R00${i + 1}`, decision: 'review' }] }));
    fixture.comparison!.strict.decisions = fixture.comparison!.baseline.decisions.map(item => ({ ...item, decision: 'block', matches: item.matches.map(match => ({ ...match, decision: 'block' })) }));
    fixture.comparison!.baseline.counts = { allow: 0, review: 6, block: 0 };
    fixture.comparison!.strict.counts = { allow: 0, review: 0, block: 6 };
    fixture.comparison!.baseline.interventions = { rule_triggered: 6, unknown_action: 0 };
    fixture.comparison!.strict.interventions = { rule_triggered: 6, unknown_action: 0 };
    fixture.comparison!.differences = fixture.events.map(event => ({ event_id: event.event_id, baseline: 'review', strict: 'block', reason: 'Backend six-rule policy explanation' }));
    fixture.unknown_coverage = [];
    const mock = mockFetch(fixture); render(<App />); const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Six-rule sample' }));
    expect(await screen.findByRole('region', { name: 'baseline summary' })).toHaveTextContent('Allow0Review6Block0');
    expect(screen.getByRole('region', { name: 'strict summary' })).toHaveTextContent('Allow0Review0Block6');
    expect(screen.getAllByRole('heading', { name: /Backend rule title/ })).toHaveLength(6);
    await user.selectOptions(screen.getByLabelText('Replay policy'), 'strict');
    expect(within(screen.getByRole('region', { name: 'Event timeline' })).getAllByRole('button', { name: /block/ })).toHaveLength(6);
    expect(mock).toHaveBeenCalledTimes(2);
    expect(mock).toHaveBeenNthCalledWith(1, '/api/samples/forensic');
  });
  it('keeps legacy fixtures inspectable without a misleading comparison', async () => {
    const fixture = structuredClone(data); delete fixture.comparison; delete fixture.unknown_coverage;
    mockFetch(fixture); render(<App />); await userEvent.click(screen.getByRole('button', { name: 'Risky sample' }));
    expect(await screen.findByText(/Legacy response: same-trace comparison is unavailable/)).toBeVisible();
    expect(screen.getByLabelText('Replay policy')).toBeDisabled();
    expect(screen.getByLabelText('Recorded event payload')).toHaveTextContent('sudo');
  });
});
