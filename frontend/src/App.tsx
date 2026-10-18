import { useState, type ChangeEvent } from 'react';
import { analyzeTrace, loadSample, MAX_BYTES } from './api';
import type { Analysis, TraceEvent } from './types';

const DISCLAIMER = 'Classifies recorded actions only. Does not execute actions or predict what an agent would do after a block.';
const PAGE_SIZE = 100;

export default function App() {
  const [raw, setRaw] = useState('');
  const [source, setSource] = useState('No trace loaded');
  const [policy, setPolicy] = useState('baseline');
  const [result, setResult] = useState<Analysis | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [page, setPage] = useState(0);

  async function analyze(text: string, name: string, chosenPolicy = policy) {
    setBusy(true); setError(''); setResult(null);
    try {
      if (new TextEncoder().encode(text).byteLength > MAX_BYTES) throw new Error('Import rejected: file exceeds 5 MiB.');
      const data = await analyzeTrace(text, chosenPolicy);
      setRaw(text); setSource(name); setResult(data); setPage(0);
      setSelected(data.events[0]?.event_id ?? null);
    } catch (err) { setError(err instanceof Error ? err.message : 'Unable to analyze trace.'); }
    finally { setBusy(false); }
  }

  async function sample(name: 'benign' | 'risky') {
    setBusy(true); setError(''); setResult(null);
    try { await analyze(await loadSample(name), `Synthetic ${name} sample`); }
    catch (err) { setError(err instanceof Error ? err.message : 'Unable to load sample.'); }
    finally { setBusy(false); }
  }

  async function upload(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    setResult(null); setError('');
    if (file.size > MAX_BYTES) { setError('Import rejected: file exceeds 5 MiB.'); return; }
    setBusy(true);
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
      await analyze(text, file.name);
    } catch { setError('Could not read file as UTF-8 JSONL.'); }
    finally { setBusy(false); }
  }

  function chooseEvent(id: string) {
    if (!result) return;
    const index = result.events.findIndex(event => event.event_id === id);
    setPage(Math.floor(index / PAGE_SIZE)); setSelected(id);
    requestAnimationFrame(() => document.getElementById(`event-${id}`)?.focus());
  }

  const active = result?.events.find(event => event.event_id === selected);
  const activeDecision = result?.decisions.find(item => item.event_id === selected);
  const linked = result?.events.filter(event => event.call_id === active?.call_id && event.event_id !== selected) ?? [];

  return <div className="app-shell">
    <a className="skip-link" href="#main">Skip to workbench</a>
    <header className="topbar">
      <a href="/" className="brand"><span className="brand-mark" aria-hidden="true">⌁</span> AgentTrace <span className="version">v0.1</span></a>
      <span className="local-badge"><span aria-hidden="true">●</span> Local analysis · no AI required</span>
    </header>
    <main id="main" className="mx-auto max-w-[1440px] px-4 py-8 md:px-8">
      <section className="intro">
        <div><p className="eyebrow">THE AGENT FLIGHT RECORDER</p><h1>Recorded actions.<br /><span>Clear evidence.</span></h1>
          <p className="subtitle">Inspect what happened. Evaluate policy decisions.<br />Keep the evidence in view.</p></div>
        <div className="scope-card"><span className="eyebrow">THIS SLICE</span><strong>01 deterministic rule</strong><p>R002 · Direct sudo / su / doas invocation</p><p>No findings ≠ proof of safety.</p></div>
      </section>

      <section aria-labelledby="import-heading" className="panel import-panel">
        <div><h2 id="import-heading">Open a trace</h2><p>UTF-8 JSONL v1.0 · up to 5 MiB · 10,000 events</p><p className="privacy">Local processing, no saved traces. Payloads are displayed as supplied; import only data you are authorized to inspect.</p></div>
        <div className="import-actions"><label className={`button primary ${busy ? 'disabled' : ''}`}>Import JSONL<input aria-label="Import JSONL" type="file" accept=".jsonl,.ndjson,application/x-ndjson" onChange={upload} disabled={busy} className="file-input" /></label>
          <button onClick={() => sample('benign')} disabled={busy}>Benign sample</button><button onClick={() => sample('risky')} disabled={busy}>Risky sample</button></div>
        <p className="synthetic-note">Both samples are synthetic. No sample actions were executed.</p>
      </section>

      <section className="replay-bar" aria-label="Policy evaluation">
        <div><label htmlFor="policy">Replay policy</label><select id="policy" value={policy} disabled={busy} onChange={e => { const value = e.target.value; setPolicy(value); if (result) void analyze(raw, source, value); }}><option value="baseline">Baseline · review privileged actions</option><option value="strict">Strict · block privileged / unknown</option></select></div>
        <p>Precedence: <strong>block &gt; review &gt; allow</strong><br />Unknown actions are never automatically allowed.</p>
      </section>
      <p className="notice">{DISCLAIMER}</p>
      <div role="status" aria-live="polite">{busy && <p className="panel status">Validating trace and evaluating recorded actions…</p>}</div>
      {error && <div role="alert" className="error"><strong>Trace not loaded</strong><p>{error}</p><p>Correct the file and import again. No partial analysis is shown.</p></div>}

      {!result && !busy && !error && <section className="empty panel"><span aria-hidden="true">⌁</span><h2>Your investigation starts here</h2><p>Import a trace, or open a synthetic sample to explore the workbench.</p></section>}

      {result && <>
        <section className="summary" aria-label="Analysis summary"><div><p className="eyebrow">{source}</p><h2>{result.trace_id}</h2><p>Policy: {result.policy.policy_id} v{result.policy.version}</p></div><div className="metrics"><div><strong>{result.events.length}</strong><span>events</span></div><div><strong>{result.findings.length}</strong><span>findings</span></div><div><strong>{result.decisions.filter(d => d.decision === 'block').length}</strong><span>blocked by policy</span></div></div></section>
        <div className="workbench">
          <section className="panel timeline" aria-labelledby="timeline-heading"><div className="section-heading"><h2 id="timeline-heading">Event timeline</h2><span>Source order</span></div>
            <ol>{result.events.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((event, index) => {
              const decision = result.decisions.find(d => d.event_id === event.event_id);
              return <li key={event.event_id}><button id={`event-${event.event_id}`} className={`event-row ${selected === event.event_id ? 'selected' : ''}`} aria-pressed={selected === event.event_id} onClick={() => setSelected(event.event_id)}><span className="event-number">{String(page * PAGE_SIZE + index + 1).padStart(2, '0')}</span><span className="event-info"><strong>{event.type === 'tool_call' ? event.tool : `Result · ${event.status}`}</strong><span>{event.event_id} · {event.timestamp}</span></span><span className={`badge ${decision?.decision ?? 'result'}`}>{decision?.decision ?? 'result'}</span></button></li>;
            })}</ol>
            {result.events.length > PAGE_SIZE && <nav className="pagination" aria-label="Timeline pages"><button disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page + 1} / {Math.ceil(result.events.length / PAGE_SIZE)}</span><button disabled={(page + 1) * PAGE_SIZE >= result.events.length} onClick={() => setPage(page + 1)}>Next</button></nav>}
          </section>
          <section className="panel evidence" aria-labelledby="evidence-heading"><div className="section-heading"><h2 id="evidence-heading">Event evidence</h2><span>{active?.event_id}</span></div>
            {active && <><dl><dt>Call ID</dt><dd>{active.call_id}</dd><dt>Recorded type</dt><dd>{active.type}</dd></dl>
              {activeDecision && <div className="decision-detail"><h3>Policy decision <span className={`badge ${activeDecision.decision}`}>{activeDecision.decision}</span></h3><ul>{activeDecision.matches.map((match, i) => <li key={i}>{match.source} → {match.decision}</li>)}</ul><p>{activeDecision.coverage_reason}</p></div>}
              {linked.length > 0 && <p className="linked">Linked events: {linked.map(event => <button key={event.event_id} onClick={() => chooseEvent(event.event_id)}>{event.event_id}</button>)}</p>}
              <h3>Recorded payload</h3><pre tabIndex={0} aria-label="Recorded event payload">{JSON.stringify(payload(active), null, 2)}</pre></>}
          </section>
        </div>
        <section className="panel findings" aria-labelledby="findings-heading"><div className="section-heading"><h2 id="findings-heading">Findings & evidence</h2><span>Rule-backed, not predictions</span></div>
          {result.findings.length === 0 ? <p>No R002 findings. Other risks are not checked in this slice.</p> : result.findings.map((finding, i) => <article key={i} className="finding"><span className="badge review">{finding.severity}</span><div><h3>{finding.rule_id} v{finding.rule_version} · Privileged execution</h3><p>{finding.message}</p><code>{finding.field}: {finding.evidence}</code><p>Evidence: {finding.event_ids.map(id => <button key={id} onClick={() => chooseEvent(id)}>{id}</button>)}</p></div></article>)}
        </section>
        {result.warnings.length > 0 && <section className="panel warnings"><h2>Trace integrity warnings</h2><ul>{result.warnings.map((warning, i) => <li key={i}>{warning.code}: {warning.event_ids.join(', ')}</li>)}</ul></section>}
        <p className="fingerprint">Source SHA-256 <code>{result.source_sha256}</code></p>
      </>}
    </main><footer>AgentTrace / local-first inspection <span>Evidence, not assurances.</span></footer>
  </div>;
}

function payload(event: TraceEvent): unknown {
  return event.type === 'tool_call' ? event.arguments : event.output;
}
