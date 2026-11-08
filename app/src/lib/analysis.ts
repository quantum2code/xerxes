// Browser-facing subset of the existing server contract. No server runtime imports.
export type ModuleKey = 'basicUrlAnalysis' | 'mlPhishingDetection' | 'httpRedirectDetection' | 'brandImpersonation' | 'blacklistCheck';
export type Evidence = { module: ModuleKey; code: string; hostname: string; target: string; [key: string]: unknown };
export type ModuleResult<T> = { module: ModuleKey; status: 'completed' | 'partial' | 'not_configured' | 'error'; evidence: Evidence[]; details: T; issues: string[] };
export type AnalysisResult = {
  validateUrl: { url: string; originalUrl: string };
  basicUrlAnalysis: ModuleResult<{ hostname: string; registrableDomain: string | null; subdomain: string | null; signals: { code: string; description: string; location: string }[] }>;
  mlPhishingDetection: ModuleResult<{ phishingProbability: number | null; threshold?: number; prediction: string | null; modelId: string | null }>;
  httpRedirectDetection: ModuleResult<{ status: string; chain: { url: string; statusCode: number; redirect?: { url: string; followed: boolean } }[]; finalUrl: string | null; crossDomain: boolean; httpsDowngrade: boolean }>;
  brandImpersonation: ModuleResult<{ brandsChecked: number; findings: { brand: string; reason: string; officialDomains: string[] }[] }>;
  blacklistCheck: ModuleResult<{ status: 'matched' | 'no_match' | 'unknown'; matches: { source: string; details?: string }[]; checkedSources: { source: string }[] }>;
  threatAssessment: { riskLevel: 'unknown' | 'low' | 'medium' | 'high'; summary: string; findings: { ruleId: string; severity: 'info' | 'medium' | 'high'; message: string; evidence: Evidence[] }[]; incompleteModules: { module: string; status: string; issues: string[] }[] };
};

export const detectors: { key: ModuleKey; name: string; description: string; number: string }[] = [
  { key: 'basicUrlAnalysis', name: 'URL structure', description: 'The small details that say a lot.', number: '01' },
  { key: 'mlPhishingDetection', name: 'Phishing detection', description: 'A second look, powered by a local model.', number: '02' },
  { key: 'httpRedirectDetection', name: 'Redirect trail', description: 'Where the link actually leads.', number: '03' },
  { key: 'brandImpersonation', name: 'Brand impersonation', description: 'Familiar names. Unfamiliar domains.', number: '04' },
  { key: 'blacklistCheck', name: 'Threat intelligence', description: 'Checked against configured threat sources.', number: '05' },
];

export function validateUrl(value: string): string | null {
  if (value.length > 8192) return 'Keep the URL under 8,192 characters.';
  try {
    const url = new URL(value);
    if (!['https:', 'http:'].includes(url.protocol) || !url.hostname || url.username || url.password) throw new Error();
    return null;
  } catch {
    return 'Enter a complete HTTP or HTTPS URL without credentials.';
  }
}

export function isAnalysisResult(value: unknown): value is AnalysisResult {
  if (!value || typeof value !== 'object') return false;
  const data = value as AnalysisResult;
  return typeof data.validateUrl?.url === 'string' && ['unknown', 'low', 'medium', 'high'].includes(data.threatAssessment?.riskLevel)
    && typeof data.threatAssessment.summary === 'string' && Array.isArray(data.threatAssessment.findings)
    && Array.isArray(data.threatAssessment.incompleteModules)
    && detectors.every(({ key }) => data[key] && typeof data[key].details === 'object' && data[key].details !== null && Array.isArray(data[key].evidence) && Array.isArray(data[key].issues));
}
