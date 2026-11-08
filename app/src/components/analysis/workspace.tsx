'use client';

import { useEffect, useRef, useState, type FormEvent } from 'react';
import { MotionConfig, useReducedMotion } from 'motion/react';
import { ArrowRight, Check, Copy, Crosshair, Globe2, Link2, LoaderCircle, LockKeyhole, RotateCcw, Shield } from 'lucide-react';
import { Button, EvidencePopover, IconSwap, Input } from '@/components/ui/primitives';
import { TextMorph } from '@/components/motion-primitives/text-morph';
import { TransitionPanel } from '@/components/motion-primitives/transition-panel';
import { DetectorCard } from './detector-card';
import { SignalDiagram } from './signal-diagram';
import { mostImportantSignal } from '@/lib/signal-state';
import { detectors, isAnalysisResult, validateUrl, type AnalysisResult, type ModuleKey } from '@/lib/analysis';

export function AnalysisWorkspace() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState('');
  const [elapsed, setElapsed] = useState<number | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const inFlight = useRef(false);
  const [run, setRun] = useState(0);
  const [waitSeconds, setWaitSeconds] = useState(0);
  const [notice, setNotice] = useState('');
  const requestRef = useRef<AbortController | null>(null);
  const reportRef = useRef<HTMLDivElement>(null);
  const reducedMotion = useReducedMotion();
  const [activeSignal, setActiveSignal] = useState<ModuleKey>('basicUrlAnalysis');

  useEffect(() => () => requestRef.current?.abort(), []);
  useEffect(() => {
    if (!loading) return;
    const start = performance.now();
    const timer = window.setInterval(() => setWaitSeconds(Math.floor((performance.now() - start) / 1000)), 1000);
    return () => window.clearInterval(timer);
  }, [loading]);
  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 2400);
    return () => window.clearTimeout(timer);
  }, [copied]);
  useEffect(() => {
    if (notice && !loading) inputRef.current?.focus();
  }, [notice, loading]);
  useEffect(() => {
    if (!result || !window.matchMedia('(max-width: 600px)').matches) return;
    reportRef.current?.focus({ preventScroll: true });
    reportRef.current?.scrollIntoView({ block: 'start', behavior: reducedMotion ? 'instant' : 'smooth' });
  }, [result, reducedMotion]);

  async function analyze(event: FormEvent) {
    event.preventDefault();
    if (inFlight.current) return;
    const trimmed = url.trim();
    const validation = validateUrl(trimmed);
    if (validation) { setError(validation); inputRef.current?.focus(); return; }
    inFlight.current = true;
    setLoading(true); setError(''); setResult(null); setElapsed(null); setCopied(false); setCopyError(''); setNotice(''); setWaitSeconds(0); setRun((value) => value + 1);
    const controller = new AbortController();
    requestRef.current = controller;
    const start = performance.now();
    try {
      const response = await fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: trimmed }), signal: AbortSignal.any([controller.signal, AbortSignal.timeout(125_000)]), cache: 'no-store' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error?.message || 'Analysis could not be completed. Please try again.');
      if (!isAnalysisResult(data)) throw new Error('The server returned an unexpected report. Please try again.');
      setActiveSignal(mostImportantSignal(data)); setResult(data); setElapsed((performance.now() - start) / 1000);
    } catch (cause) {
      if (controller.signal.aborted) setNotice('Scan cancelled. Your URL is ready to edit.');
      else setError(cause instanceof Error && cause.name === 'TimeoutError' ? 'The analysis timed out. Please try again.' : cause instanceof Error ? cause.message : 'Unable to connect. Please try again.');
    } finally { setLoading(false); inFlight.current = false; requestRef.current = null; }
  }

  function reset() { if (loading) return; setResult(null); setUrl(''); setError(''); setElapsed(null); setCopied(false); setCopyError(''); setNotice(''); inputRef.current?.focus(); }
  async function copyUrl() {
    if (!result) return;
    try { await navigator.clipboard.writeText(result.validateUrl.url); setCopied(true); setCopyError(''); }
    catch { setCopyError('Clipboard unavailable. Select and copy the URL below.'); }
  }

  const parsed = result ? new URL(result.validateUrl.url) : null;
  const completed = result ? detectors.filter(({ key }) => result[key].status === 'completed').length : 0;
  const risk = result?.threatAssessment.riskLevel;
  const verdict = risk === 'high' ? 'High-risk signals detected.' : risk === 'medium' ? 'There’s reason to look closer.' : risk === 'low' ? 'Low risk. Still, stay aware.' : 'The picture is incomplete.';

  return <MotionConfig reducedMotion="user"><div className="horizon" aria-hidden="true"><div className="horizon-orb" /></div><div className="site-wrap">
    <header className="site-header"><a className="wordmark" href="/" aria-label="Xerxes home"><span className="brand-mark"><Crosshair size={19} strokeWidth={1.4} /></span>xerxes</a></header>

    <main>
      <div className="page-intro"><h1>Look closer. <span>Click wiser.</span></h1></div>

      <div className="workspace">
        <aside className="sidebar">
          <section className="input-section"><h2>Analyze a URL</h2>
            <form onSubmit={analyze} noValidate>
              <label htmlFor="url">URL to inspect</label>
              <div className={`url-input-wrap ${error ? 'has-error' : ''}`}><Link2 size={16} /><Input ref={inputRef} id="url" type="url" value={url} onChange={(event) => { setUrl(event.target.value); setError(''); setNotice(''); }} placeholder="https://example.com" autoComplete="off" autoCapitalize="none" spellCheck={false} disabled={loading} aria-invalid={Boolean(error)} aria-describedby={error ? 'url-error privacy-note' : 'privacy-note'} /></div>
              <Button type="submit" variant="primary" className="analyze-button" aria-label={loading ? 'Analyzing URL' : 'Analyze URL'} disabled={loading}>
                <TextMorph>{loading ? 'Analyzing URL' : 'Analyze URL'}</TextMorph>
                <IconSwap active={loading}>{[<ArrowRight size={16} key="arrow" />, <LoaderCircle size={16} className="spin" key="spinner" />]}</IconSwap>
              </Button>
              {loading && <div className="scan-wait"><span className="wait-label">{waitSeconds >= 15 ? 'Taking a little longer…' : 'Inspecting the URL…'} <span className="mono">{waitSeconds}s</span></span><Button type="button" onClick={() => requestRef.current?.abort()}>Cancel scan</Button></div>}
              <div className="form-feedback"><TransitionPanel activeIndex={error ? 1 : notice ? 2 : 0}>{[<span key="none" />, <p key="error" id="url-error" role="alert" className="form-error">{error}</p>, <p key="notice" className="scan-notice" role="status">{notice}</p>]}</TransitionPanel></div>
            </form>
            <p className="privacy-note" id="privacy-note"><LockKeyhole size={12} />Don’t submit private links or URLs containing secrets. Configured providers may receive the full URL.</p>
          </section>

          {result && <section className="url-overview">
            <div className="section-top"><h2>URL details</h2><div className="copy-action"><span className="copy-caption">{copied ? 'Copied' : ''}</span><Button variant="icon" aria-label={copied ? 'URL copied' : 'Copy normalized URL'} onClick={copyUrl}><IconSwap active={copied}>{[<Copy size={15} key="copy" />, <Check size={15} key="check" />]}</IconSwap></Button></div></div>
            <dl className="metadata"><div><dt>Protocol</dt><dd>{parsed?.protocol.replace(':', '').toUpperCase()}</dd></div><div><dt>Domain</dt><dd>{result.basicUrlAnalysis.details.registrableDomain || '—'}</dd></div><div><dt>Subdomain</dt><dd>{result.basicUrlAnalysis.details.subdomain || 'None'}</dd></div><div><dt>Destination</dt><dd>{result.httpRedirectDetection.details.finalUrl || '—'}</dd></div></dl>
            <div className="normalized-url"><span>Normalized URL</span><p className="mono">{result.validateUrl.url}</p></div>
            <span className="sr-only" role="status">{copied ? 'URL copied to clipboard.' : copyError}</span>{copyError && <p className="form-error">{copyError}</p>}
          </section>}
        </aside>

        <div className="report-area" ref={reportRef} tabIndex={-1} aria-label="Investigation report" aria-busy={loading}>
          <div className="report-toolbar"><span className="report-state"><span className={`status-dot ${loading ? 'pulsing' : ''}`} />{loading ? 'In progress' : result ? `Finished · ${completed} of 5 checks available` : 'Ready to analyze'}</span><Button onClick={reset} disabled={loading || (!result && !url)}><RotateCcw size={14} /> New scan</Button></div>

          <section className={`assessment-card ${risk ? `risk-${risk}` : ''} ${result ? '' : 'assessment-explore'}`} data-evidence-card aria-labelledby="assessment-title"><div className="assessment-top"><Shield size={15} aria-hidden="true" /><span className={`assessment-badge ${risk || ''}`}>{loading ? 'ANALYZING' : risk ? `${risk.toUpperCase()} RISK` : 'AWAITING INPUT'}</span></div>
            <TransitionPanel activeIndex={loading ? 1 : result ? 2 : 0} className="assessment-transition">{[
              <div className="assessment-content assessment-idle" key="ready"><div><h2 id="assessment-title">Trust starts with<br />a closer look.</h2></div><SignalDiagram active={activeSignal} onSelect={setActiveSignal} /></div>,
              <div className="assessment-content assessment-idle" key="loading"><div><h2 id="assessment-title">Following the evidence.</h2></div><SignalDiagram active={activeSignal} onSelect={setActiveSignal} loading /></div>,
              <div className="assessment-content completed-assessment assessment-with-diagram" key="report"><div><h2 id="assessment-title">{verdict}</h2>{parsed && <div className="assessment-target"><Globe2 size={14} /><span className="mono">{parsed.hostname}</span></div>}<p>{result?.threatAssessment.summary}</p></div>{result && <SignalDiagram active={activeSignal} onSelect={setActiveSignal} result={result} />}</div>,
            ]}</TransitionPanel>
            {result && result.threatAssessment.findings.length > 0 && <EvidencePopover title="Assessment evidence" preview={<p>{result.threatAssessment.summary}</p>}><ul className="findings-list">{result.threatAssessment.findings.map((finding, i) => <li key={`${finding.ruleId}-${i}`}><span className={`finding-severity ${finding.severity}`}>{finding.severity}</span>{finding.message}</li>)}</ul></EvidencePopover>}
            {result && <div className="assessment-meta"><span><span className="mono">{completed}/5</span> checks</span><span>{result.threatAssessment.findings.length} {result.threatAssessment.findings.length === 1 ? 'finding' : 'findings'}</span>{elapsed !== null && <span className="mono">{elapsed.toFixed(1)}s</span>}</div>}
          </section>

          {result && result.threatAssessment.incompleteModules.length > 0 && <div className="incomplete-notice" role="status">{result.threatAssessment.incompleteModules.length} {result.threatAssessment.incompleteModules.length === 1 ? 'check' : 'checks'} incomplete: {result.threatAssessment.incompleteModules.map((item) => detectors.find((detector) => detector.key === item.module)?.name || item.module).join(', ')}. Missing evidence is not an all-clear.</div>}
          <div className="checks-heading"><h2>Checks</h2></div>
          {result || loading ? <div className="detector-grid" key={run}>{detectors.map(({ key }) => <DetectorCard key={key} kind={key} result={result} loading={loading} active={key === activeSignal} />)}</div> : <ul className="check-preview-list">{detectors.map(({ key, name }) => <li key={key} data-active={key === activeSignal || undefined} onPointerEnter={() => setActiveSignal(key)}>{name}</li>)}</ul>}
          <p className="report-disclaimer">Automated checks can miss threats or flag legitimate URLs. No assessment guarantees safety.</p>
          <div className="sr-only" role="status">{loading ? 'Analysis in progress.' : result ? `Analysis complete. ${risk} risk. ${completed} of 5 checks completed.` : ''}</div>
        </div>
      </div>
    </main>
  </div></MotionConfig>;
}
