import { render, screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from '../src/App';
import { analyzeTrace } from '../src/api';
import type { Analysis } from '../src/types';

const data: Analysis = {
  trace_id: 'synthetic-risky', source_sha256: 'abc123', policy: { policy_id: 'baseline', version: '1.0' },
  events: [{ schema_version: '1.0', trace_id: 'synthetic-risky', event_id: 'e1', timestamp: '2026-10-18T10:00:00Z', call_id: 'c1', type: 'tool_call', tool: 'process.exec', arguments: { argv: ['sudo', 'id'], cwd: '/workspace', shell: false } },
    { schema_version: '1.0', trace_id: 'synthetic-risky', event_id: 'e2', timestamp: '2026-10-18T10:00:01Z', call_id: 'c1', type: 'tool_result', status: 'ok', output: '<script>window.hacked=true</script>' }],
  findings: [{ rule_id: 'R002', rule_version: '1.0', severity: 'high', event_ids: ['e1'], field: 'arguments.argv[0]', evidence: 'sudo', message: 'Direct privileged executable invocation.' }],
  decisions: [{ event_id: 'e1', call_id: 'c1', decision: 'review', matches: [{ source: 'rule:R002', decision: 'review' }], coverage: 'limited', coverage_reason: 'Only R002 is checked.' }],
  warnings: [], disclaimer: 'Recorded actions only.',
};
function mockFetch() {
  const mock = vi.fn(async (url: string) => {
    if (url.includes('/samples/')) return new Response(JSON.stringify({ synthetic: true, jsonl: '{"synthetic":true}' }));
    const strict = url.includes('strict');
    return new Response(JSON.stringify({ ...data, policy: { policy_id: strict ? 'strict' : 'baseline', version: '1.0' }, decisions: data.decisions.map(d => ({ ...d, decision: strict ? 'block' : 'review' })) }));
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
    expect(screen.getByRole('heading', { name: /R002 v1.0/ })).toBeVisible();
    expect(screen.getByText('rule:R002 → review')).toBeVisible();
    const timeline = screen.getByRole('region', { name: 'Event timeline' });
    await user.click(within(timeline).getByRole('button', { name: /Result/ }));
    expect(screen.getByLabelText('Recorded event payload')).toHaveTextContent('<script>window.hacked=true</script>');
    expect(document.querySelector('script')).toBeNull();
    await user.click(within(screen.getByRole('region', { name: 'Findings & evidence' })).getByRole('button', { name: 'e1' }));
    expect(screen.getByLabelText('Recorded event payload')).toHaveTextContent('sudo');
    await user.selectOptions(screen.getByLabelText('Replay policy'), 'strict');
    await waitFor(() => expect(screen.getByText('Policy: strict v1.0')).toBeVisible());
    expect(mock).toHaveBeenLastCalledWith('/api/analyze?policy=strict', expect.objectContaining({ method: 'POST', body: '{"synthetic":true}' }));
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
    vi.stubGlobal('fetch', vi.fn(async (url: string) => url.includes('samples')
      ? new Response(JSON.stringify({ jsonl: 'invalid' }))
      : new Response(JSON.stringify({ error: { code: 'invalid_event', line: 2 } }), { status: 422 })));
    render(<App />); await userEvent.click(screen.getByRole('button', { name: 'Benign sample' }));
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
});
