import { useState, type ChangeEvent, type ReactNode } from 'react';
import { analyzeTrace, loadSample, MAX_BYTES, SafeError, safeMessage } from './api';
import type { Analysis, TraceEvent } from './types';

const DISCLAIMER = 'Classifies recorded actions only. Does not execute actions or predict what an agent would do after a block.';
const PAGE_SIZE = 100;

export default function App() {
  const [source, setSource] = useState('No trace loaded');
  const [policy, setPolicy] = useState('baseline');
  const [result, setResult] = useState<Analysis | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [demo, setDemo] = useState(false);
  const [exportStatus, setExportStatus] = useState('');
  const [exportError, setExportError] = useState(false);

  async function analyze(text: string, name: string, chosenPolicy = policy) {
    setBusy(true); setError(''); setResult(null); setExportStatus('');
    try {
      if (new TextEncoder().encode(text).byteLength > MAX_BYTES) throw new SafeError('Import rejected: file exceeds 5 MiB.');
      const data = await analyzeTrace(text, chosenPolicy);
      setSource(name); setResult(data); setPage(0);
      setSelected(data.events[0]?.event_id ?? null);
    } catch (err) { setError(safeMessage(err, 'Unable to analyze trace. Check the backend connection and try again.')); }
    finally { setBusy(false); }
  }

  async function sample(name: 'benign' | 'risky' | 'forensic', guided = false) {
    setDemo(guided); setBusy(true); setError(''); setResult(null); setExportStatus('');
    try { await analyze(await loadSample(name), `Synthetic ${name} sample`); }
    catch (err) { setError(safeMessage(err, 'Unable to load sample. Check the backend connection and try again.')); }
    finally { setBusy(false); }
  }

  async function upload(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    setResult(null); setError(''); setDemo(false); setExportStatus('');
    if (file.size > MAX_BYTES) { setError('Import rejected: file exceeds 5 MiB.'); return; }
    setBusy(true);
    try {
      const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(await file.arrayBuffer());
      await analyze(text, 'Imported JSONL');
    } catch { setError('Could not read file as UTF-8 JSONL.'); }
    finally { setBusy(false); }
  }

  function chooseEvent(id: string) {
    if (!result) return;
    const index = result.events.findIndex(event => event.event_id === id);
    if (index < 0) return;
    setPage(Math.floor(index / PAGE_SIZE)); setSelected(id);
    requestAnimationFrame(() => document.getElementById(`event-${id}`)?.focus());
  }

  const active = result?.events.find(event => event.event_id === selected);
  const run = result?.comparison?.[policy as 'baseline' | 'strict'];
  const decisions = run?.decisions ?? result?.decisions ?? [];
  const activeDecision = decisions.find(item => item.event_id === selected);
  const interventions = decisions.filter(item => item.decision !== 'allow');
  const linked = result?.events.filter(event => event.call_id === active?.call_id && event.event_id !== selected) ?? [];
  const reports = result?.reports;
  const canExport = Boolean(!busy && reports?.format_version === '1.0' && typeof reports.json === 'string' && typeof reports.markdown === 'string' && /^[a-f0-9]{64}$/i.test(result?.source_sha256 ?? ''));

  function download(format: 'json' | 'markdown') {
    if (!canExport || !result || !reports) return;
    let url: string | undefined;
    let anchor: HTMLAnchorElement | undefined;
    try {
      url = URL.createObjectURL(new Blob([reports[format]], { type: format === 'json' ? 'application/json;charset=utf-8' : 'text/markdown;charset=utf-8' }));
      anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `agenttrace-report-${result.source_sha256.slice(0, 12).toLowerCase()}.${format === 'json' ? 'json' : 'md'}`;
      document.body.append(anchor); anchor.click();
      setExportError(false); setExportStatus(`${format === 'json' ? 'JSON' : 'Markdown'} report download requested.`);
    } catch {
      setExportError(true); setExportStatus('Report download failed. Try again; your analysis is still available.');
    } finally {
      const objectUrl = url; const link = anchor;
      setTimeout(() => { link?.remove(); if (objectUrl) URL.revokeObjectURL(objectUrl); }, 0);
    }
  }

  const reportPanel = <section id="reports" className="panel report-panel" aria-labelledby="reports-heading"><h2 id="reports-heading">Sanitized analysis reports</h2><p>Backend-produced findings and decisions, excluding raw event arguments and output.</p><div className="report-actions"><button disabled={!canExport} onClick={() => download('json')}>Download JSON</button><button disabled={!canExport} onClick={() => download('markdown')}>Download Markdown</button></div>{!result && <p>Analyze a trace to enable report downloads.</p>}{result && !canExport && <p>Analyzed reports are unavailable for this response.</p>}{result && <p className="fingerprint">Report SHA-256 <code>{reports?.report_sha256 ?? 'Unavailable'}</code> · exact UTF-8 report JSON text bytes</p>}<p className={exportError ? 'export-error' : ''} role="status" aria-live="polite" aria-label="Report download status">{exportStatus}</p></section>;

  return <div className="app-shell">
    <a className="skip-link" href="#main">Skip to workbench</a>
    <header className="topbar">
      <a href="/" className="brand"><span className="brand-mark" aria-hidden="true">⌁</span> AgentTrace <span className="version">v0.1</span></a>
      <span className="local-badge"><span aria-hidden="true">●</span> Local analysis · no AI required</span>
    </header>
    <main id="main" tabIndex={-1} className="mx-auto max-w-[1440px] px-4 py-8 md:px-8">
      <section className={`intro${result ? ' intro-compact' : ''}`}>
        <div><p className="eyebrow">THE AGENT FLIGHT RECORDER</p><h1>Recorded actions.<br /><span>Clear evidence.</span></h1>
          <p className="subtitle">Inspect what happened. Evaluate policy decisions.<br />Keep the evidence in view.</p></div>
        <div className="scope-card"><span className="eyebrow">THIS SLICE</span><strong>06 deterministic rules</strong><p>Bounded checks of recorded actions</p><p>No findings ≠ proof of safety.</p></div>
      </section>

      <section aria-labelledby="import-heading" className="panel import-panel">
        <div><h2 id="import-heading">Open a trace</h2><p>UTF-8 JSONL v1.0 · up to 5 MiB · 10,000 events</p><p className="privacy">Local processing, no saved traces. Evidence is sanitized by the backend; heuristic redaction may miss sensitive data. Inspect reports before sharing.</p></div>
        <div className="import-actions"><label className={`button primary ${busy ? 'disabled' : ''}`}>Import JSONL<input aria-label="Import JSONL" type="file" accept=".jsonl,.ndjson,application/x-ndjson" onChange={upload} disabled={busy} className="file-input" /></label>
          <button onClick={() => sample('forensic', true)} disabled={busy}>Explore demo</button><button onClick={() => sample('benign')} disabled={busy}>Benign sample</button><button onClick={() => sample('risky')} disabled={busy}>Risky sample</button><button onClick={() => sample('forensic')} disabled={busy}>Six-rule sample</button></div>
        <p className="synthetic-note">All samples are synthetic. No sample actions were executed.</p>
      </section>

      <section className="replay-bar" aria-label="Policy evaluation">
        <div><label htmlFor="policy">Replay policy</label><select id="policy" value={policy} disabled={busy || Boolean(result && !result.comparison)} onChange={e => setPolicy(e.target.value)}><option value="baseline">Baseline · review rule matches</option><option value="strict">Strict · block rule matches / unknown</option></select></div>
        <p>Precedence: <strong>block &gt; review &gt; allow</strong><br />Unknown actions are never automatically allowed.</p>
      </section>
      <p className="notice">{DISCLAIMER}</p>
      {!result && reportPanel}
      <div role="status" aria-live="polite">{busy && <p className="panel status">Validating trace and evaluating recorded actions…</p>}</div>
      {error && <div role="alert" className="error"><strong>Trace not loaded</strong><p>{error}</p><p>Correct the file and import again. No partial analysis is shown.</p></div>}

      {!result && !busy && !error && <section className="empty panel"><span aria-hidden="true">⌁</span><h2>Your investigation starts here</h2><p>Import a trace, or open a synthetic sample to explore the workbench.</p></section>}

      {result && <>
        <nav className="section-nav" aria-label="Analysis sections"><a href="#comparison">Compare policies</a><a href="#timeline-heading">Timeline</a><a href="#findings-heading">Findings</a><a href="#interventions-heading">Interventions</a><a href="#unknown-heading">Unknown coverage</a><a href="#reports">Reports</a></nav>
        <section className="notice" aria-label="Sanitization notice"><h2>Heuristic redaction · {result.sanitization.redactions} redactions</h2><p>Heuristics may miss secrets. Review before sharing; redaction is not a guarantee of confidentiality.</p><details><summary tabIndex={0}>Redaction scope and evidence references</summary><p>{result.sanitization.notice}</p><p>{result.sanitization.reference_semantics}</p></details></section>
        <section className="summary" aria-label="Analysis summary"><div><p className="eyebrow">{source}</p><h2>{result.trace_id}</h2><p>Policy: {(run ?? result).policy.policy_id} v{(run ?? result).policy.version}</p></div><div className="metrics"><div><strong>{result.events.length}</strong><span>events</span></div><div><strong>{result.findings.length}</strong><span>findings</span></div><div><strong>{decisions.filter(d => d.decision === 'block').length}</strong><span>blocked by policy</span></div></div></section>
        <p className="fingerprint">Same trace · Source SHA-256 <code>{result.source_sha256}</code> · exact input bytes, before sanitization</p>
        <section id="comparison" className="comparison-intro" aria-labelledby="comparison-heading"><p className="eyebrow">SAME RECORDING · TWO POLICIES</p><h2 id="comparison-heading">Why policy decisions differ</h2><p>Baseline reviews rule matches. Strict blocks rule matches and applies stricter handling to unknown coverage. Follow each backend explanation to the recorded evidence.</p></section>
        {result.comparison ? <>
          <div className="comparison" aria-label="Same-trace policy comparison">{(['baseline', 'strict'] as const).map(name => {
            const item = result.comparison![name];
            return <section className="panel policy-card" key={name} aria-label={`${name} summary`}><h2>{name === 'baseline' ? 'Baseline' : 'Strict'} · v{item.policy.version}</h2><dl><dt>Allow</dt><dd>{item.counts.allow}</dd><dt>Review</dt><dd>{item.counts.review}</dd><dt>Block</dt><dd>{item.counts.block}</dd><dt>Rule-triggered interventions</dt><dd>{item.interventions.rule_triggered}</dd><dt>Unknown-action interventions</dt><dd>{item.interventions.unknown_action}</dd></dl><p>Intervention categories can overlap; do not add them together.</p></section>;
          })}</div>
          {demo && <section className="panel demo-guide" aria-labelledby="demo-heading"><h2 id="demo-heading">Explore demo · synthetic forensic recording</h2><ol><li>Compare Baseline and Strict on the same recorded trace above.</li><li>Choose an action under policy differences to inspect its evidence.</li><li>Switch replay policy locally, then download the sanitized analysis report.</li></ol><p>Synthetic examples only. No sample actions were executed.</p></section>}
          <section className="panel collection" aria-labelledby="differences-heading"><h2 id="differences-heading">Per-action policy differences</h2><PagedList key={`differences-${result.source_sha256}`} label="Differences" items={result.comparison.differences} empty="No policy changes for this trace." render={item => <article><button onClick={() => chooseEvent(item.event_id)}>{item.event_id}</button><p>Baseline {item.baseline} → Strict {item.strict}</p><p>Why change: {bounded(item.reason)}</p></article>} /></section>
        </> : <p className="notice">Legacy response: same-trace comparison is unavailable.</p>}
        <div className="workbench">
          <section className="panel timeline" aria-labelledby="timeline-heading"><div className="section-heading"><h2 id="timeline-heading">Event timeline</h2><span>Source order</span></div>
            <ol>{result.events.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((event, index) => {
              const decision = decisions.find(d => d.event_id === event.event_id);
              return <li key={event.event_id}><button id={`event-${event.event_id}`} className={`event-row ${selected === event.event_id ? 'selected' : ''}`} aria-pressed={selected === event.event_id} onClick={() => setSelected(event.event_id)}><span className="event-number">{String(page * PAGE_SIZE + index + 1).padStart(2, '0')}</span><span className="event-info"><strong>{event.type === 'tool_call' ? event.tool : `Result · ${event.status}`}</strong><span>{event.event_id} · {event.timestamp}</span></span><span className={`badge ${decision?.decision ?? 'result'}`}>{decision?.decision ?? 'result'}</span></button></li>;
            })}</ol>
            {result.events.length > PAGE_SIZE && <nav className="pagination" aria-label="Timeline pages"><button disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page + 1} / {Math.ceil(result.events.length / PAGE_SIZE)}</span><button disabled={(page + 1) * PAGE_SIZE >= result.events.length} onClick={() => setPage(page + 1)}>Next</button></nav>}
          </section>
          <section className="panel evidence" aria-labelledby="evidence-heading"><div className="section-heading"><h2 id="evidence-heading">Event evidence</h2><span>{active?.event_id}</span></div>
            {active && <><dl><dt>Call ID</dt><dd>{active.call_id}</dd><dt>Recorded type</dt><dd>{active.type}</dd></dl>
              {activeDecision && <div className="decision-detail"><h3>Policy decision <span className={`badge ${activeDecision.decision}`}>{activeDecision.decision}</span></h3><ul>{activeDecision.matches.map((match, i) => <li key={i}>{match.source} → {match.decision}</li>)}</ul><p>Analysis coverage: {activeDecision.coverage}</p><p>{bounded((activeDecision.coverage_reasons ?? [activeDecision.coverage_reason]).join('; '))}</p><p>Intervention sources: {activeDecision.intervention_sources?.join(', ') || 'None recorded'}</p>{activeDecision.recorded_continuation_after_block && <p>Recorded continuation after hypothetical block <button onClick={() => chooseEvent(activeDecision.blocked_by_event_id!)}>{activeDecision.blocked_by_event_id}</button> — not a prediction</p>}</div>}
              {linked.length > 0 && <p className="linked">Linked events: {linked.map(event => <button key={event.event_id} onClick={() => chooseEvent(event.event_id)}>{event.event_id}</button>)}</p>}
              <h3>Sanitized recorded payload</h3><pre tabIndex={0} aria-label="Recorded event payload">{bounded(payload(active))}</pre></>}
          </section>
        </div>
        <section className="panel findings" aria-labelledby="findings-heading"><div className="section-heading"><h2 id="findings-heading">Findings & evidence</h2><span>Rule-backed observations, not policy decisions or predictions</span></div>
          <p>High severity prioritizes a matched risk signature for review; it does not confirm harm. Evidence values are sanitized; offsets refer to the original input.</p>
          <PagedList key={`findings-${result.source_sha256}`} label="Findings" items={result.findings} empty="No rule-backed findings. This is not proof of safety; checks are limited to the six-rule scope." render={finding => <article className="finding"><span className="badge review">{finding.severity}</span><div><h3>{finding.rule_id} v{finding.rule_version} · {finding.title ?? 'Rule finding'}</h3><p>{bounded(finding.message)}</p>{(finding.evidence_items ?? [{ field: finding.field, value: finding.evidence, truncated: false }]).map((item, i) => <div key={i}><code>{item.field}: {bounded(item.value)}</code>{item.truncated && <p>Evidence truncated by engine.</p>}</div>)}{finding.limitations && <p>Limitations: {bounded(finding.limitations)}</p>}<p>Evidence: {finding.event_ids.map(id => <button key={id} onClick={() => chooseEvent(id)}>{id}</button>)}</p></div></article>} />
        </section>
        <section className="panel collection" aria-labelledby="interventions-heading"><h2 id="interventions-heading">Policy interventions</h2><p>Selected policy: {policy}. Categories are independent and may overlap.</p><PagedList key={`interventions-${policy}-${result.source_sha256}`} label="Interventions" items={interventions} empty="No policy interventions for this trace." render={item => <article><button onClick={() => chooseEvent(item.event_id)}>{item.event_id}</button> <span className={`badge ${item.decision}`}>{item.decision}</span><p>Sources: {item.intervention_sources?.join(', ') || item.matches.map(match => match.source).join(', ')}</p>{item.recorded_continuation_after_block && <p>Recorded continuation after hypothetical block <button onClick={() => chooseEvent(item.blocked_by_event_id!)}>{item.blocked_by_event_id}</button> — not a prediction</p>}</article>} /></section>
        <section className="panel collection" aria-labelledby="unknown-heading"><h2 id="unknown-heading">Unknown analysis coverage</h2><p>Coverage gaps, not findings. Unknown actions are never automatically allowed.</p><PagedList key={`unknown-${result.source_sha256}`} label="Unknown coverage" items={result.unknown_coverage ?? []} empty={result.unknown_coverage ? 'No unknown analysis coverage reported.' : 'Coverage details unavailable in this legacy response.'} render={item => <article><button onClick={() => chooseEvent(item.event_id)}>{item.event_id}</button><p>{bounded(item.reasons.join('; '))}</p></article>} /></section>
        {reportPanel}
        {result.warnings.length > 0 && <section className="panel warnings"><h2>Trace integrity warnings</h2><PagedList key={`warnings-${result.source_sha256}`} label="Warnings" items={result.warnings} empty="No integrity warnings." render={warning => <p>{warning.code}: {warning.event_ids.map(id => <button key={id} onClick={() => chooseEvent(id)}>{id}</button>)}</p>} /></section>}
      </>}
    </main><footer>AgentTrace / local-first inspection <span>Evidence, not assurances.</span></footer>
  </div>;
}

function payload(event: TraceEvent): unknown {
  return event.type === 'tool_call' ? event.arguments : event.output;
}

function bounded(value: unknown): string {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2) ?? '';
  return text.length > 8192 ? `${text.slice(0, 8192)}\n[Truncated: showing first 8192 code units]` : text;
}

function PagedList<T>({ items, label, empty, render }: { items: T[]; label: string; empty: string; render: (item: T) => ReactNode }) {
  const [page, setPage] = useState(0);
  if (!items.length) return <p>{empty}</p>;
  return <><p>{label}: {items.length} total · showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, items.length)}</p>{items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((item, index) => <div key={page * PAGE_SIZE + index}>{render(item)}</div>)}{items.length > PAGE_SIZE && <nav className="pagination" aria-label={`${label} pages`}><button disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page + 1} / {Math.ceil(items.length / PAGE_SIZE)}</span><button disabled={(page + 1) * PAGE_SIZE >= items.length} onClick={() => setPage(page + 1)}>Next</button></nav>}</>;
}
