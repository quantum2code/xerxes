export const severities = ['informational', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = typeof severities[number];
export type Confidence = 'low' | 'medium' | 'high';
export type ScanMode = 'passive' | 'active';
export type ScanStatus = 'completed' | 'partial' | 'blocked' | 'failed';

export interface Finding {
  id: string;
  checkId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  affectedUrl: string;
  evidence: { location: string; observation: string }[];
  cwe: string[];
  owasp: string[];
  cves: string[];
  remediation: string;
  source: 'native' | 'zap';
  detectedAt: string;
}
export type FindingInput = Omit<Finding, 'id' | 'detectedAt' | 'source' | 'cwe' | 'owasp' | 'cves'> & {
  source?: Finding['source']; cwe?: string[]; owasp?: string[]; cves?: string[];
};
export interface ScanResult {
  schemaVersion: '1.0';
  targetUrl: string;
  mode: ScanMode;
  status: ScanStatus;
  durationMs: number;
  checksExecuted: string[];
  checksSkipped: { checkId: string; reason: string }[];
  counts: Record<Severity, number>;
  coverageLimitations: string[];
  findings: Finding[];
  backend: { native: 'available'; zap: 'disabled' | 'unavailable' | 'completed' | 'failed' | 'blocked' };
}
export interface ScanRequest { url: string; mode?: ScanMode; authorizationToken?: string; }
export interface Page {
  url: string;
  status: number;
  headers: Record<string, string | string[]>;
  body: string;
}
export interface Check {
  id: string;
  run(page: Page): FindingInput[];
}
/** Trusted application configuration, never populated directly from request JSON. */
export interface AuthorizationGrant {
  token: string;
  origin: string;
  modes: ScanMode[];
  expiresAt: string;
}
export interface ScannerConfig {
  requestTimeoutMs: number;
  scanTimeoutMs: number;
  maxResponseBytes: number;
  maxRequests: number;
  maxRedirects: number;
  maxDepth: number;
  requestIntervalMs: number;
  maxConcurrentScans: number;
  grants: AuthorizationGrant[];
  requirePassiveAuthorization: boolean;
  zap: { enabled: boolean; image: string; gatewayImage: string; timeoutMs: number };
}
