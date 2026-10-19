import { useMemo, useState, type ChangeEvent, type ReactNode } from 'react';
import { analyzeTrace, loadSample, MAX_BYTES, SafeError, safeMessage } from './api';
import type { Analysis, Decision, PolicyDecision, TraceEvent } from './types';
import { DecisionPill, Icon, MetricCard, PolicyFlow, PolicySummaryCard, type IconName } from './visuals';

const DISCLAIMER = 'Classifies recorded actions only. Does not execute actions or predict what an agent would do after a block.';
const PAGE_SIZE = 100;
const NAV_ITEMS = [
  ['Overview', '#overview'],
  ['Timeline', '#timeline-heading'],
  ['Findings', '#findings-heading'],
  ['Policy Replay', '#comparison'],
  ['Evidence & coverage', '#evidence-heading'],
  ['Reports', '#reports'],
] as const;

type TimelineFilter = 'all' | 'tool_call' | 'tool_result' | 'interventions';

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
  const [timelineFilter, setTimelineFilter] = useState<TimelineFilter>('all');
  const [timelineQuery, setTimelineQuery] = useState('');
  const [copyStatus, setCopyStatus] = useState('');

  async function analyze(text: string, name: string, chosenPolicy = policy) {
    setBusy(true); setError(''); setResult(null); setExportStatus(''); setCopyStatus('');
    try {
      if (new TextEncoder().encode(text).byteLength > MAX_BYTES) throw new SafeError('Import rejected: file exceeds 5 MiB.');
      const data = await analyzeTrace(text, chosenPolicy);
      setSource(name); setResult(data); setPage(0); setTimelineFilter('all'); setTimelineQuery('');
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
    setResult(null); setError(''); setDemo(false); setExportStatus(''); setCopyStatus('');
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
    setTimelineFilter('all'); setTimelineQuery(''); setPage(Math.floor(index / PAGE_SIZE)); setSelected(id);
    requestAnimationFrame(() => document.getElementById(`event-${id}`)?.focus());
  }

  async function copyIdentifier(value: string, label: string) {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(value);
      setCopyStatus(`${label} copied.`);
    } catch { setCopyStatus(`${label} is visible above; clipboard access was unavailable.`); }
  }

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

  const active = result?.events.find(event => event.event_id === selected);
  const run = result?.comparison?.[policy as 'baseline' | 'strict'];
  const decisions = run?.decisions ?? result?.decisions ?? [];
  const activeDecision = decisions.find(item => item.event_id === selected);
  const interventions = decisions.filter(item => item.decision !== 'allow');
  const linked = result?.events.filter(event => event.call_id === active?.call_id && event.event_id !== selected) ?? [];
  const reports = result?.reports;
  const canExport = Boolean(!busy && reports?.format_version === '1.0' && typeof reports.json === 'string' && typeof reports.markdown === 'string' && /^[a-f0-9]{64}$/i.test(result?.source_sha256 ?? ''));
  const timelineEvents = useMemo(() => {
    if (!result) return [];
    const query = timelineQuery.trim().toLowerCase();
    return result.events.filter(event => {
      const matchesFilter = timelineFilter === 'all'
        || event.type === timelineFilter
        || (timelineFilter === 'interventions' && decisions.some(item => item.event_id === event.event_id && item.decision !== 'allow'));
      const searchable = `${event.event_id} ${event.call_id} ${event.type === 'tool_call' ? event.tool : event.status} ${event.timestamp}`.toLowerCase();
      return matchesFilter && (!query || searchable.includes(query));
    });
  }, [decisions, result, timelineFilter, timelineQuery]);
  const timelinePageCount = Math.max(1, Math.ceil(timelineEvents.length / PAGE_SIZE));
  const visibleTimelineEvents = timelineEvents.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const reportPanel = <section id="reports" className="panel report-panel" aria-labelledby="reports-heading">
    <div className="panel-heading report-heading"><div className="heading-icon"><Icon name="file" aria-hidden="true" /></div><div><p className="eyebrow">Close the loop</p><h2 id="reports-heading">Sanitized analysis reports</h2></div><span className="panel-index">06</span></div>
    <p>Backend-produced findings and decisions, excluding raw event arguments and output.</p>
    <div className="report-actions"><button type="button" disabled={!canExport} onClick={() => download('json')}><Icon name="file" size={15} aria-hidden="true" />Download JSON</button><button type="button" disabled={!canExport} onClick={() => download('markdown')}><Icon name="file" size={15} aria-hidden="true" />Download Markdown</button></div>
    {!result && <p className="muted-note">Analyze a trace to enable report downloads.</p>}
    {result && !canExport && <p className="muted-note">Analyzed reports are unavailable for this response.</p>}
    {result && <p className="fingerprint">Report SHA-256 <code>{reports?.report_sha256 ?? 'Unavailable'}</code> · exact UTF-8 report JSON text bytes</p>}
    <p className={exportError ? 'export-error' : 'status-line'} role="status" aria-live="polite" aria-label="Report download status">{exportStatus}</p>
  </section>;

  return <div className="app-shell">
    <a className="skip-link" href="#main">Skip to workbench</a>
    <header className="topbar">
      <a href="/" className="brand" aria-label="AgentTrace home">
        <span className="brand-mark" aria-hidden="true"><Icon name="activity" size={20} /></span>
        <span className="brand-copy"><strong>AgentTrace</strong><small>Forensic workbench</small></span>
        <span className="version">v0.1</span>
      </a>
      <div className="topbar-meta"><span className="local-badge"><span className="status-dot" aria-hidden="true" />Local analysis · no AI required</span><span className="topbar-separator" aria-hidden="true" /> <span className="topbar-note">Recorded actions only</span></div>
    </header>

    <main id="main" tabIndex={-1} className="main-shell">
      <section id="overview" className={`hero${result ? ' intro-compact' : ''}`} aria-labelledby="hero-heading">
        <div className="hero-copy">
          <div className="eyebrow hero-eyebrow"><span className="eyebrow-line" aria-hidden="true" />THE AGENT FLIGHT RECORDER</div>
          <h1 id="hero-heading">Recorded behavior.<br /><span>Explained with evidence.</span></h1>
          <p className="subtitle">Forensic replay for autonomous agents.<br />Understand what happened, then see how policy changes the outcome.</p>
          <div className="hero-assurances" aria-label="AgentTrace principles"><span><Icon name="shield-check" size={14} aria-hidden="true" />Deterministic</span><span><Icon name="lock" size={14} aria-hidden="true" />Sanitized by default</span><span><Icon name="zap" size={14} aria-hidden="true" />No actions executed</span></div>
        </div>
        <div className="hero-signal" aria-label="Investigation scope">
          <div className="signal-top"><span className="signal-orbit" aria-hidden="true"><span /></span><span className="signal-label">INVESTIGATION SCOPE</span><span className="signal-code">AT / 01</span></div>
          <div className="signal-rule" aria-hidden="true" />
          <strong>06 deterministic rules</strong>
          <p>Bounded checks of recorded tool activity.</p>
          <div className="signal-foot"><span className="status-dot" aria-hidden="true" />Local-first analysis</div>
        </div>
      </section>

      <section aria-labelledby="import-heading" className="panel import-panel">
        <div className="import-copy"><div className="panel-heading"><div className="heading-icon heading-icon-accent"><Icon name="layers" aria-hidden="true" /></div><div><p className="eyebrow">Start an investigation</p><h2 id="import-heading">Load a trace</h2></div><span className="panel-index">01</span></div><p>UTF-8 JSONL v1.0 · up to 5 MiB · 10,000 events</p><p className="privacy"><Icon name="lock" size={14} aria-hidden="true" />Local processing, no saved traces. Evidence is sanitized by the backend; heuristic redaction may miss sensitive data.</p></div>
        <div className="import-control"><div className="import-actions"><label className={`button primary file-button ${busy ? 'disabled' : ''}`}><Icon name="file" size={16} aria-hidden="true" />Import JSONL<input aria-label="Import JSONL" type="file" accept=".jsonl,.ndjson,application/x-ndjson" onChange={upload} disabled={busy} className="file-input" /></label><button type="button" onClick={() => sample('forensic', true)} disabled={busy}><Icon name="zap" size={16} aria-hidden="true" />Explore demo</button><button type="button" onClick={() => sample('benign')} disabled={busy}>Benign sample</button><button type="button" onClick={() => sample('risky')} disabled={busy}>Risky sample</button><button type="button" onClick={() => sample('forensic')} disabled={busy}>Six-rule sample</button></div><p className="synthetic-note"><span aria-hidden="true">↳</span> All samples are synthetic. No sample actions were executed.</p></div>
      </section>

      <section className="replay-bar" aria-label="Policy evaluation">
        <div className="replay-label"><div className="heading-icon heading-icon-blue"><Icon name="shield" aria-hidden="true" /></div><div><label htmlFor="policy">Replay policy</label><p>Evaluate the same recorded trace locally.</p></div></div>
        <select id="policy" value={policy} disabled={busy || Boolean(result && !result.comparison)} aria-describedby="policy-help" onChange={e => { setPolicy(e.target.value); setPage(0); }}><option value="baseline">Baseline · review rule matches</option><option value="strict">Strict · block rule matches / unknown</option></select>
        <div id="policy-help" className="precedence"><span className="precedence-label">Precedence</span><span className="mini-decision mini-decision-block">block</span><span className="precedence-arrow" aria-hidden="true">›</span><span className="mini-decision mini-decision-review">review</span><span className="precedence-arrow" aria-hidden="true">›</span><span className="mini-decision mini-decision-allow">allow</span></div>
      </section>
      <p className="notice notice-inline"><Icon name="fingerprint" size={15} aria-hidden="true" /><span>{DISCLAIMER}</span></p>
      {!result && reportPanel}
      <div role="status" aria-live="polite">{busy && <p className="panel status"><span className="loading-spinner" aria-hidden="true" />Validating trace and evaluating recorded actions…</p>}</div>
      {error && <div role="alert" className="error"><div className="error-icon"><Icon name="alert-triangle" aria-hidden="true" /></div><div><strong>Trace not loaded</strong><p>{error}</p><p>Correct the file and import again. No partial analysis is shown.</p></div></div>}

      {!result && !busy && !error && <section className="empty panel" aria-labelledby="empty-heading"><div className="empty-icon"><Icon name="activity" aria-hidden="true" /></div><div><p className="eyebrow">Ready when you are</p><h2 id="empty-heading">Your investigation starts here</h2><p>Import a trace, or open a synthetic sample to explore the workbench.</p></div><div className="empty-steps"><span><b>01</b> Load</span><span><b>02</b> Inspect</span><span><b>03</b> Replay</span></div></section>}

      {result && <>
        <nav className="section-nav" aria-label="Analysis sections"><span className="section-nav-label">Investigation</span>{NAV_ITEMS.map(([label, href]) => <a key={href} href={href}>{label}</a>)}</nav>

        <section className="notice notice-warning" aria-labelledby="sanitization-heading"><div className="notice-icon"><Icon name="shield-alert" aria-hidden="true" /></div><div><h2 id="sanitization-heading">Heuristic redaction · {result.sanitization.redactions} redactions</h2><p>Heuristics may miss secrets. Review before sharing; redaction is not a guarantee of confidentiality.</p><details><summary tabIndex={0}>Redaction scope and evidence references</summary><p>{result.sanitization.notice}</p><p>{result.sanitization.reference_semantics}</p></details></div></section>

        <section className="analysis-summary" aria-label="Analysis summary">
          <div className="summary-identity"><p className="eyebrow">{source}</p><h2>{result.trace_id}</h2><p className="summary-policy"><span className="status-dot" aria-hidden="true" />Policy: {(run ?? result).policy.policy_id} v{(run ?? result).policy.version}</p><p className="summary-disclaimer">Same source recording · decisions are deterministic and local.</p></div>
          <div className="summary-metrics"><MetricCard label="Recorded events" value={result.events.length} detail="Source order preserved" icon="activity" tone="accent" /><MetricCard label="Rule findings" value={result.findings.length} detail="Six bounded checks" icon="alert-triangle" tone={result.findings.length ? 'review' : 'neutral'} /><MetricCard label="Policy blocks" value={decisions.filter(d => d.decision === 'block').length} detail={`${policy} replay`} icon="ban" tone={decisions.some(d => d.decision === 'block') ? 'block' : 'neutral'} /></div>
        </section>
        <p className="fingerprint source-fingerprint"><Icon name="fingerprint" size={14} aria-hidden="true" />Source SHA-256 <code>{result.source_sha256}</code><span>exact input bytes, before sanitization</span></p>

        <section id="comparison" className="comparison-section" aria-labelledby="comparison-heading"><div className="section-intro"><div><p className="eyebrow">02 · SAME RECORDING · TWO POLICIES</p><h2 id="comparison-heading">See the intervention boundary</h2><p>One trace, two deterministic readings. The comparison makes every changed decision traceable to a rule match or an unknown-coverage intervention.</p></div><span className="section-count"><Icon name="arrow-right" size={14} aria-hidden="true" /> Replay locally</span></div>
          {result.comparison ? <>
            <div className="comparison-layout"><div className="panel policy-flow-panel"><PolicyFlow baseline={result.comparison.baseline.counts} strict={result.comparison.strict.counts} heading="Decision distribution" description="Recorded actions classified under each bundled policy." /><div className="flow-note"><span className="flow-note-line flow-note-line-review" />Baseline reviews rule matches <span className="flow-note-separator">·</span><span className="flow-note-line flow-note-line-block" />Strict blocks rule matches and unknown coverage</div></div><div className="policy-summary-grid">{(['baseline', 'strict'] as const).map(name => { const item = result.comparison![name]; return <section className={`policy-summary-region ${name}`} key={name} aria-label={`${name} summary`}><PolicySummaryCard policy={item.policy} counts={item.counts} interventions={item.interventions} description={name === 'baseline' ? 'Review signatures; keep the recording intact.' : 'Block signatures and unknown coverage.'} /></section>; })}</div></div>
            {demo && <section className="panel demo-guide" aria-labelledby="demo-heading"><div className="demo-guide-mark"><span>DEMO</span><Icon name="zap" size={16} aria-hidden="true" /></div><div><h2 id="demo-heading">Explore demo · synthetic forensic recording</h2><p className="demo-lead">A guided pass through the forensic workflow.</p><ol><li><span>01</span><div><strong>Compare the replay</strong><small>See how baseline and strict classify the same events.</small></div></li><li><span>02</span><div><strong>Follow a changed action</strong><small>Open an evidence-linked difference in the timeline.</small></div></li><li><span>03</span><div><strong>Export the conclusion</strong><small>Download a sanitized report when you are ready.</small></div></li></ol><p className="synthetic-note">Synthetic examples only. No sample actions were executed.</p></div></section>}
            <section className="panel collection differences-panel" aria-labelledby="differences-heading"><div className="section-heading"><div><p className="eyebrow">Decision deltas</p><h2 id="differences-heading">Per-action policy differences</h2></div><span className="section-heading-meta">{result.comparison.differences.length} changed actions</span></div><p className="collection-intro">Each transition stays linked to the original event and its backend explanation.</p><PagedList key={`differences-${result.source_sha256}`} label="Differences" items={result.comparison.differences} empty="No policy changes for this trace." render={item => <article className="difference-row"><div className="difference-event"><button type="button" onClick={() => chooseEvent(item.event_id)}>{item.event_id}</button><span className="difference-arrow" aria-hidden="true"><Icon name="arrow-right" size={15} /></span></div><div className="decision-transition"><span>Baseline <strong className={`decision-word decision-word-${item.baseline}`}>{item.baseline}</strong></span><Icon name="arrow-right" size={14} aria-hidden="true" /><span>Strict <strong className={`decision-word decision-word-${item.strict}`}>{item.strict}</strong></span></div><p>Why change: {bounded(item.reason)}</p></article>} /></section>
          </> : <p className="notice notice-inline">Legacy response: same-trace comparison is unavailable.</p>}
        </section>

        <div className="workbench-heading"><div><p className="eyebrow">03 · TRACE INSPECTION</p><h2>Move from signal to evidence</h2></div><p>Select any recorded event to keep context while you investigate.</p></div>
        <div className="workbench">
          <section className="panel timeline" aria-labelledby="timeline-heading"><div className="section-heading timeline-heading"><div><p className="eyebrow">Source order</p><h2 id="timeline-heading">Event timeline</h2></div><span className="section-heading-meta">{timelineEvents.length} of {result.events.length} events</span></div><div className="timeline-tools"><label><span>Filter</span><select aria-label="Timeline filter" value={timelineFilter} onChange={e => { setTimelineFilter(e.target.value as TimelineFilter); setPage(0); }}><option value="all">All recorded events</option><option value="tool_call">Tool calls</option><option value="tool_result">Tool results</option><option value="interventions">Policy interventions</option></select></label><label className="timeline-search"><span className="sr-only">Search events by ID, tool, or time</span><Icon name="search" size={15} aria-hidden="true" /><input aria-label="Search events by ID, tool, or time" type="search" value={timelineQuery} placeholder="Search event or tool" onChange={e => { setTimelineQuery(e.target.value); setPage(0); }} /></label></div>
            {visibleTimelineEvents.length ? <ol className="timeline-list">{visibleTimelineEvents.map((event, index) => { const decision = decisions.find(d => d.event_id === event.event_id); const sourceIndex = result.events.findIndex(item => item.event_id === event.event_id); const label = event.type === 'tool_call' ? event.tool : `Result · ${event.status}`; return <li key={event.event_id} className="timeline-item"><span className="timeline-rail" aria-hidden="true" /><button type="button" id={`event-${event.event_id}`} className={`event-row ${selected === event.event_id ? 'selected' : ''}`} aria-pressed={selected === event.event_id} onClick={() => setSelected(event.event_id)}><span className="event-index">{String(sourceIndex + 1).padStart(2, '0')}</span><span className={`event-glyph ${event.type}`}><Icon name={eventIcon(event)} size={16} aria-hidden="true" /></span><span className="event-info"><strong>{label}</strong><span>{event.event_id} <i aria-hidden="true">·</i> {event.timestamp}</span></span>{decision ? <DecisionPill decision={decision.decision} label={decision.decision} showIcon={false} /> : <span className="result-badge">Recorded result</span>}<Icon name="chevron-right" size={16} className="event-chevron" aria-hidden="true" /></button></li>; })}</ol> : <div className="timeline-empty"><Icon name="search" size={20} aria-hidden="true" /><strong>No events match this view</strong><p>Clear the filter or search to return to the full recording.</p></div>}
            {timelineEvents.length > PAGE_SIZE && <nav className="pagination" aria-label="Timeline pages"><button type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button><span>Page {Math.min(page + 1, timelinePageCount)} / {timelinePageCount}</span><button type="button" disabled={(page + 1) * PAGE_SIZE >= timelineEvents.length} onClick={() => setPage(page + 1)}>Next</button></nav>}
          </section>

          <section className="panel evidence" aria-labelledby="evidence-heading"><div className="section-heading evidence-heading"><div><p className="eyebrow">Linked source context</p><h2 id="evidence-heading">Event evidence</h2></div><span className="evidence-id">{active?.event_id ?? 'No selection'}</span></div>{active ? <><div className="evidence-context"><div className="evidence-context-icon"><Icon name={eventIcon(active)} size={18} aria-hidden="true" /></div><div><strong>{active.type === 'tool_call' ? active.tool : `Tool result · ${active.status}`}</strong><p>Recorded at {active.timestamp}</p></div><span className="context-index">{String(result.events.findIndex(event => event.event_id === active.event_id) + 1).padStart(2, '0')} / {String(result.events.length).padStart(2, '0')}</span></div><dl className="evidence-meta"><div><dt>Event ID</dt><dd><code>{active.event_id}</code><button type="button" className="copy-button" onClick={() => copyIdentifier(active.event_id, 'Event ID')}><Icon name="file" size={13} aria-hidden="true" />Copy</button></dd></div><div><dt>Call ID</dt><dd><code>{active.call_id}</code><button type="button" className="copy-button" onClick={() => copyIdentifier(active.call_id, 'Call ID')}><Icon name="file" size={13} aria-hidden="true" />Copy</button></dd></div><div><dt>Recorded type</dt><dd>{active.type}</dd></div></dl>{activeDecision && <div className="decision-detail"><div className="decision-detail-heading"><h3>Policy decision</h3><DecisionPill decision={activeDecision.decision} /></div><ul className="match-list">{activeDecision.matches.length ? activeDecision.matches.map((match, i) => <li key={i}><span className="match-dot" aria-hidden="true" /><span>{match.source} → {match.decision}</span></li>) : <li>No rule match recorded.</li>}</ul><div className="coverage-row"><span>Analysis coverage</span><strong className={`coverage-${activeDecision.coverage}`}>{activeDecision.coverage}</strong></div><p>{bounded((activeDecision.coverage_reasons ?? [activeDecision.coverage_reason]).join('; '))}</p><p>Intervention sources: {activeDecision.intervention_sources?.join(', ') || 'None recorded'}</p>{activeDecision.recorded_continuation_after_block && <p className="continuation-note"><Icon name="alert" size={14} aria-hidden="true" />Recorded continuation after hypothetical block <button type="button" onClick={() => activeDecision.blocked_by_event_id && chooseEvent(activeDecision.blocked_by_event_id)}>{activeDecision.blocked_by_event_id}</button> — not a prediction</p>}</div>}{linked.length > 0 && <p className="linked"><span>Linked events</span>{linked.map(event => <button type="button" key={event.event_id} onClick={() => chooseEvent(event.event_id)}>{event.event_id}</button>)}</p>}<div className="payload-heading"><h3>Sanitized recorded payload</h3><span>read-only · bounded excerpt</span></div><pre tabIndex={0} aria-label="Recorded event payload">{bounded(payload(active))}</pre><p className="copy-status" role="status" aria-live="polite">{copyStatus}</p></> : <div className="evidence-empty"><Icon name="fingerprint" size={24} aria-hidden="true" /><strong>Select an event to inspect its evidence</strong><p>Findings and policy differences will bring you here automatically.</p></div>}</section>
        </div>

        <section className="panel findings" aria-labelledby="findings-heading"><div className="section-heading"><div><p className="eyebrow">04 · RULE-BACKED OBSERVATIONS</p><h2 id="findings-heading">Findings &amp; evidence</h2></div><span className="section-heading-meta">{result.findings.length} findings</span></div><p className="section-description">High severity prioritizes a matched risk signature for review; it does not confirm harm. Evidence values are sanitized; offsets refer to the original input.</p><PagedList key={`findings-${result.source_sha256}`} label="Findings" items={result.findings} empty="No rule-backed findings. This is not proof of safety; checks are limited to the six-rule scope." render={finding => <article className="finding"><div className="finding-severity"><span className={`severity-badge severity-${severityTone(finding.severity)}`}>{finding.severity}</span><span className="finding-rule">{finding.rule_id} · {finding.rule_version}</span></div><div><h3>{finding.rule_id} v{finding.rule_version} · {finding.title ?? 'Rule finding'}</h3><p>{bounded(finding.message)}</p><div className="evidence-items">{(finding.evidence_items ?? [{ field: finding.field, value: finding.evidence, truncated: false }]).map((item, i) => <div key={i} className="evidence-item"><code><span>{item.field}</span>{bounded(item.value)}</code>{item.truncated && <p>Evidence truncated by engine.</p>}</div>)}</div>{finding.limitations && <p className="limitation"><Icon name="alert" size={13} aria-hidden="true" />Limitations: {bounded(finding.limitations)}</p>}<p className="finding-links"><span>Evidence:</span>{finding.event_ids.map(id => <button type="button" key={id} onClick={() => chooseEvent(id)}>{id}</button>)}</p></div></article>} /></section>

        <div className="coverage-grid"><section className="panel collection" aria-labelledby="interventions-heading"><div className="section-heading"><div><p className="eyebrow">05 · POLICY RESPONSE</p><h2 id="interventions-heading">Policy interventions</h2></div><span className="section-heading-meta">{interventions.length} non-allow</span></div><p className="section-description">Selected policy: <strong>{policy}</strong>. Categories are independent and may overlap.</p><PagedList key={`interventions-${policy}-${result.source_sha256}`} label="Interventions" items={interventions} empty="No policy interventions for this trace." render={item => <article className="coverage-row-item"><div><button type="button" onClick={() => chooseEvent(item.event_id)}>{item.event_id}</button><DecisionPill decision={item.decision} /></div><p>Sources: {item.intervention_sources?.join(', ') || item.matches.map(match => match.source).join(', ') || 'No source recorded'}</p>{item.recorded_continuation_after_block && <p className="continuation-note"><Icon name="alert" size={13} aria-hidden="true" />Recorded continuation after hypothetical block <button type="button" onClick={() => item.blocked_by_event_id && chooseEvent(item.blocked_by_event_id)}>{item.blocked_by_event_id}</button> — not a prediction</p>}</article>} /></section><section className="panel collection" aria-labelledby="unknown-heading"><div className="section-heading"><div><p className="eyebrow">COVERAGE BOUNDARIES</p><h2 id="unknown-heading">Unknown analysis coverage</h2></div><span className="section-heading-meta">{result.unknown_coverage?.length ?? 0} gaps</span></div><p className="section-description">Coverage gaps, not findings. Unknown actions are never automatically allowed.</p><PagedList key={`unknown-${result.source_sha256}`} label="Unknown coverage" items={result.unknown_coverage ?? []} empty={result.unknown_coverage ? 'No unknown analysis coverage reported.' : 'Coverage details unavailable in this legacy response.'} render={item => <article className="coverage-row-item"><button type="button" onClick={() => chooseEvent(item.event_id)}>{item.event_id}</button><p>{bounded(item.reasons.join('; '))}</p></article>} /></section></div>

        {reportPanel}
        {result.warnings.length > 0 && <section className="panel warnings" aria-labelledby="warnings-heading"><div className="section-heading"><div><p className="eyebrow">INTEGRITY</p><h2 id="warnings-heading">Trace integrity warnings</h2></div><span className="section-heading-meta">{result.warnings.length} warnings</span></div><PagedList key={`warnings-${result.source_sha256}`} label="Warnings" items={result.warnings} empty="No integrity warnings." render={warning => <p>{warning.code}: {warning.event_ids.map(id => <button type="button" key={id} onClick={() => chooseEvent(id)}>{id}</button>)}</p>} /></section>}
      </>}
    </main>
    <footer><span><span className="footer-mark" aria-hidden="true" />AgentTrace / local-first inspection</span><span>Evidence, not assurances.</span></footer>
  </div>;
}

function eventIcon(event: TraceEvent): IconName {
  if (event.type === 'tool_result') return event.status === 'error' ? 'alert-triangle' : 'check';
  const tool = event.tool.toLowerCase();
  if (tool.includes('exec') || tool.includes('shell') || tool.includes('command')) return 'terminal';
  if (tool.includes('file') || tool.includes('write') || tool.includes('delete')) return 'file';
  if (tool.includes('http') || tool.includes('fetch') || tool.includes('request')) return 'activity';
  if (tool.includes('secret') || tool.includes('credential') || tool.includes('auth')) return 'lock';
  return 'zap';
}

function severityTone(value: string): 'high' | 'medium' | 'low' {
  const normalized = value.toLowerCase();
  if (normalized === 'critical' || normalized === 'high') return 'high';
  if (normalized === 'medium' || normalized === 'moderate') return 'medium';
  return 'low';
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
  if (!items.length) return <p className="collection-empty">{empty}</p>;
  return <><p className="collection-meta">{label}: {items.length} total · showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, items.length)}</p><div className="paged-items">{items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((item, index) => <div key={page * PAGE_SIZE + index}>{render(item)}</div>)}</div>{items.length > PAGE_SIZE && <nav className="pagination" aria-label={`${label} pages`}><button type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page + 1} / {Math.ceil(items.length / PAGE_SIZE)}</span><button type="button" disabled={(page + 1) * PAGE_SIZE >= items.length} onClick={() => setPage(page + 1)}>Next</button></nav>}</>;
}
