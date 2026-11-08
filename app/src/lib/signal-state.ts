import { detectors, type AnalysisResult, type ModuleKey } from './analysis';

export type SignalTone = 'idle' | 'pending' | 'complete' | 'notice' | 'warning' | 'alert' | 'unknown';
export type SignalState = {
  tone: SignalTone;
  label: string;
  metric: string;
  detail: string;
  incomplete: boolean;
};

export function getSignalState(key: ModuleKey, result: AnalysisResult | null, loading = false): SignalState {
  if (loading) return { tone: 'pending', label: 'Analyzing', metric: 'Pending', detail: '', incomplete: false };
  if (!result) return { tone: 'idle', label: 'Not analyzed', metric: '', detail: '', incomplete: false };

  const module = result[key];
  const findings = result.threatAssessment.findings.filter((finding) => finding.evidence?.some((item) => item.module === key));
  const high = findings.find((finding) => finding.severity === 'high');
  const warning = findings.find((finding) => finding.severity === 'medium');
  let metric = '';
  let detail = '';
  let flagged = findings.length > 0;
  let unavailable = false;

  switch (key) {
    case 'basicUrlAnalysis': {
      const { signals } = result.basicUrlAnalysis.details;
      metric = `${signals.length} ${signals.length === 1 ? 'signal' : 'signals'}`;
      detail = signals[0]?.description || 'No structural flags reported.';
      flagged ||= signals.length > 0;
      break;
    }
    case 'mlPhishingDetection': {
      const { phishingProbability, prediction } = result.mlPhishingDetection.details;
      unavailable = phishingProbability === null;
      metric = unavailable ? 'Unavailable' : `${(phishingProbability! * 100).toFixed(1)}%`;
      detail = unavailable ? 'No model prediction available.' : prediction === 'phishing'
        ? 'The model flagged phishing-like URL patterns. This is not an overall safety score.'
        : 'The model did not classify the URL as phishing. This is not an overall safety score.';
      flagged ||= prediction === 'phishing';
      break;
    }
    case 'httpRedirectDetection': {
      const { chain, status, crossDomain, httpsDowngrade } = result.httpRedirectDetection.details;
      const hops = chain.filter((hop) => hop.redirect?.followed).length;
      metric = `${hops} ${hops === 1 ? 'hop' : 'hops'}`;
      unavailable = status !== 'complete';
      detail = unavailable ? `Redirect inspection stopped: ${status}.` : 'Redirect inspection completed.';
      if (httpsDowngrade) detail += ' HTTPS was downgraded to HTTP.';
      else if (crossDomain) detail += ' A cross-domain destination was observed.';
      flagged ||= crossDomain || httpsDowngrade;
      break;
    }
    case 'brandImpersonation': {
      const { findings: brands, brandsChecked } = result.brandImpersonation.details;
      metric = `${brands.length} ${brands.length === 1 ? 'lookalike' : 'lookalikes'}`;
      detail = brands.length ? `Possible lookalikes: ${brands.map((brand) => brand.brand).join(', ')}.` : `${brandsChecked} brands checked; no lookalikes reported.`;
      flagged ||= brands.length > 0;
      break;
    }
    case 'blacklistCheck': {
      const { status, checkedSources, matches } = result.blacklistCheck.details;
      unavailable = status === 'unknown';
      metric = status === 'matched' ? 'Match' : status === 'no_match' ? 'No match' : 'Unavailable';
      detail = status === 'matched' ? `Potentially unsafe URL reported by ${matches.map((match) => match.source).join(', ')}.`
        : status === 'no_match' ? 'No configured source matched. This does not establish safety.'
        : checkedSources.length ? 'Threat sources did not return a conclusive result.' : 'No threat sources configured.';
      flagged ||= status === 'matched';
      break;
    }
  }

  const incomplete = module.status !== 'completed' || unavailable
    || result.threatAssessment.incompleteModules.some((item) => item.module === key);
  // Only backend high-severity findings produce red. ML scores, observation
  // counts, and the global verdict must never invent a detector's severity.
  const tone: SignalTone = high ? 'alert' : warning ? 'warning' : incomplete ? 'unknown' : flagged ? 'notice' : 'complete';
  const label = high ? 'High severity' : warning ? 'Warning' : incomplete
    ? module.status === 'not_configured' ? 'Not configured' : 'Incomplete'
    : flagged ? 'Review signal' : 'Completed';
  const explanation = high?.message || warning?.message || detail;
  return {
    tone,
    label: (high || warning) && incomplete ? `${label} · incomplete` : label,
    metric: incomplete && !flagged ? 'Unavailable' : metric,
    detail: incomplete && module.issues[0] ? `${explanation} ${module.issues[0]}` : explanation,
    incomplete,
  };
}

export function mostImportantSignal(result: AnalysisResult): ModuleKey {
  const rank: Record<SignalTone, number> = { idle: 0, pending: 0, complete: 1, unknown: 2, notice: 3, warning: 4, alert: 5 };
  return detectors.reduce((best, current) => rank[getSignalState(current.key, result).tone] > rank[getSignalState(best, result).tone]
    ? current.key : best, detectors[0].key);
}
