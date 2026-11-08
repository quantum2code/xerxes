'use client';

import { Braces, BrainCircuit, Route, Fingerprint, ShieldCheck, CircleCheck, CircleHelp } from 'lucide-react';
import { EvidencePopover, IconSwap } from '@/components/ui/primitives';
import { TransitionPanel } from '@/components/motion-primitives/transition-panel';
import { detectors, type AnalysisResult, type ModuleKey } from '@/lib/analysis';

const icons = { basicUrlAnalysis: Braces, mlPhishingDetection: BrainCircuit, httpRedirectDetection: Route, brandImpersonation: Fingerprint, blacklistCheck: ShieldCheck };

function readable(value: unknown): string {
  if (Array.isArray(value)) return value.map(readable).join(', ');
  if (value && typeof value === 'object') return JSON.stringify(value);
  return String(value ?? '—');
}

export function DetectorCard({ kind, result, loading, active = false }: { kind: ModuleKey; result: AnalysisResult | null; loading: boolean; active?: boolean }) {
  const config = detectors.find((item) => item.key === kind)!;
  const Icon = icons[kind];
  const module = result?.[kind];
  const complete = module?.status === 'completed';
  const label = loading ? 'Analyzing' : !module ? 'Awaiting URL' : complete ? 'Completed' : module.status === 'not_configured' ? 'Not configured' : 'Incomplete';

  return <section className={`detector-card ${module ? 'has-result' : 'is-preview'} ${kind === 'blacklistCheck' ? 'wide-card' : ''}`} data-evidence-card data-selected={active || undefined} aria-labelledby={`${kind}-title`}>
    <div className="card-heading"><div className="card-icon"><Icon size={16} strokeWidth={1.5} /></div><h3 id={`${kind}-title`}>{config.name}</h3></div>
    <div className="detector-body">
      <TransitionPanel activeIndex={module ? 1 : 0} variants={{ enter: { opacity: 0 }, center: { opacity: 1 }, exit: { opacity: 0, transition: { duration: 0.06 } } }}>{[
        <div key="pending"><div className="check-skeleton" aria-hidden="true"><span /><span /></div></div>,
        module && result ? <DetectorContent key="result" kind={kind} result={result} /> : null,
      ]}</TransitionPanel>
    </div>
    <div className="detector-footer"><span className={`check-status ${module && !complete ? 'tone-amber' : ''}`}><IconSwap active={complete}>{[<CircleHelp size={13} key="unknown" />, <CircleCheck size={13} key="done" />]}</IconSwap>{label}</span>{module ? <span className="mono">{module.evidence.length} {module.evidence.length === 1 ? 'signal' : 'signals'}</span> : <span className="mono">—</span>}</div>
    {module && <EvidencePopover title={`${config.name} evidence`} preview={result ? <DetectorContent kind={kind} result={result} /> : undefined}>
      {module.issues.length > 0 && <div className="issue-list"><h4>Check limitations</h4>{module.issues.map((issue, i) => <p key={i}>{issue}</p>)}</div>}
      {module.evidence.length === 0 ? <p>No evidence signals were returned by this detector.</p> : module.evidence.map((evidence, i) => <div className="evidence-record" key={i}><h4>{evidence.code.replaceAll('_', ' ').toLowerCase()}</h4><dl>{Object.entries(evidence).filter(([key]) => key !== 'code').map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{readable(value)}</dd></div>)}</dl></div>)}
    </EvidencePopover>}
  </section>;
}

function DetectorContent({ kind, result }: { kind: ModuleKey; result: AnalysisResult }) {
  switch (kind) {
    case 'basicUrlAnalysis': {
      const { signals } = result.basicUrlAnalysis.details;
      return <><div className="metric">{signals.length}<span>structural signals</span></div>{signals.length > 0 && <div className="signal-chips">{signals.map((signal, i) => <span className="signal-chip" key={i}>{signal.code.replaceAll('_', ' ')}</span>)}</div>}</>;
    }
    case 'mlPhishingDetection': {
      const detail = result.mlPhishingDetection.details;
      const probability = detail.phishingProbability;
      return <><div className="metric">{probability === null ? '—' : `${(probability * 100).toFixed(1)}%`}<span>model phishing score</span></div><div className="score-track" aria-hidden="true"><span style={{ width: `${(probability ?? 0) * 100}%` }} />{detail.threshold !== undefined && <i style={{ left: `${detail.threshold * 100}%` }} />}</div><p>{probability === null ? 'No model prediction available.' : detail.prediction === 'phishing' ? 'Phishing-like URL patterns detected.' : 'Not classified as phishing.'}</p>{detail.threshold !== undefined && <span className="micro mono">Threshold · {(detail.threshold * 100).toFixed(0)}%</span>}</>;
    }
    case 'httpRedirectDetection': {
      const detail = result.httpRedirectDetection.details;
      return <><div className="metric">{detail.chain.filter((hop) => hop.redirect?.followed).length}<span>followed redirects</span></div><ol className="redirect-chain">{detail.chain.map((hop, i) => <li key={i}><span className="chain-dot" /><span className="mono">{hop.url}</span><span className="http-code mono">{hop.statusCode}</span></li>)}</ol>{(detail.status !== 'complete' || detail.crossDomain || detail.httpsDowngrade) && <p>{detail.status !== 'complete' ? `Inspection stopped: ${detail.status}.` : ''}{detail.crossDomain ? ' Cross-domain destination.' : ''}{detail.httpsDowngrade ? ' HTTPS downgrade.' : ''}</p>}</>;
    }
    case 'brandImpersonation': {
      const detail = result.brandImpersonation.details;
      return <><div className="metric">{detail.findings.length}<span>potential lookalikes</span></div><p>{detail.brandsChecked} brands checked</p>{detail.findings.length > 0 && <div className="signal-chips">{detail.findings.map((finding, i) => <span className="signal-chip tone-amber" key={i}>{finding.brand} · {finding.reason.replaceAll('_', ' ')}</span>)}</div>}</>;
    }
    case 'blacklistCheck': {
      const detail = result.blacklistCheck.details;
      const google = detail.matches.some((match) => match.source === 'google-safe-browsing');
      return <><div className="intelligence-result"><div><div className="result-title">{detail.status === 'matched' ? 'Potentially unsafe URL' : detail.status === 'no_match' ? 'No known matches' : 'Not enough information'}</div><p>{detail.status === 'no_match' ? 'No configured source matched this URL. This does not establish that it is safe.' : detail.status === 'matched' ? 'One or more configured threat sources returned a match.' : 'Threat sources were unavailable or not configured. This check is inconclusive.'}</p></div><span className="source-count mono">{detail.checkedSources.length}<small>sources checked</small></span></div><div className="signal-chips">{detail.checkedSources.map((source) => <span className="signal-chip" key={source.source}>{source.source}</span>)}</div>{detail.matches.map((match, i) => <p className="provider-detail" key={i}>{match.details || `Match from ${match.source}`}</p>)}{google && <div className="google-advisory"><a href="https://developers.google.com/safe-browsing/v4/advisory" target="_blank" rel="noreferrer">Advisory provided by Google ↗</a><span>Learn more: <a href="https://www.antiphishing.org/" target="_blank" rel="noreferrer">Phishing</a> · <a href="https://developers.google.com/search/docs/monitor-debug/security/malware" target="_blank" rel="noreferrer">Malware</a> · <a href="https://www.google.com/about/unwanted-software-policy.html" target="_blank" rel="noreferrer">Unwanted software</a></span></div>}</>;
    }
  }
}
