import { z } from 'zod';

export const statusSchema = z.enum(['completed', 'partial', 'blocked', 'failed', 'cancelled', 'skipped', 'unavailable']);
export type ScanStatus = z.infer<typeof statusSchema>;
export const modeSchema = z.enum(['passive', 'active']);
export type ScanMode = z.infer<typeof modeSchema>;
export const requestSchema = z.object({
  url: z.string().min(1).max(4096), mode: modeSchema.default('passive'),
  authorizationId: z.string().min(1).max(100), authorizationToken: z.string().min(32).max(512),
  policy: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/).default('conservative'),
});
export type Engine2ScanRequest = z.infer<typeof requestSchema>;
export const scopeRulesSchema = z.object({
  hosts: z.array(z.object({ hostname: z.string().min(1).max(253), includeSubdomains: z.boolean().default(false) })).min(1).max(16),
  protocols: z.array(z.enum(['http:', 'https:'])).min(1).max(2),
  ports: z.array(z.number().int().min(1).max(65535)).min(1).max(16),
  paths: z.array(z.string().max(1024)).min(1).max(32).default(['/']),
  excludedPaths: z.array(z.string().max(1024)).max(64).default(['/logout', '/signout', '/account/delete', '/delete-account', '/checkout', '/payment', '/purchase']),
  activeMethods: z.array(z.enum(['GET', 'HEAD', 'POST', 'OPTIONS'])).min(1).max(4).default(['GET', 'HEAD']),
  profile: z.enum(['public', 'isolated-lab']).default('public'),
});
export type ScopeRules = z.infer<typeof scopeRulesSchema>;
export const grantSchema = z.object({
  id: z.string().min(1).max(100), tokenSha256: z.string().regex(/^[a-f0-9]{64}$/),
  expiresAt: z.iso.datetime(), crawlAuthorized: z.literal(true), rules: scopeRulesSchema,
  activeVerification: z.object({ verifiedBy: z.string().min(1).max(100), evidenceRef: z.string().min(1).max(256), verifiedAt: z.iso.datetime() }).optional(),
  allowedPolicies: z.array(z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/)).max(16).default(['conservative']),
});
export type AuthorizationGrant = z.infer<typeof grantSchema>;
export interface Engine2Error { stage: 'scope' | 'zap' | 'spider' | 'passive' | 'active' | 'orchestrator'; code: string; message: string; }
export interface ScopeValidationResult {
  status: ScanStatus; errors: Engine2Error[]; approved: boolean; normalizedTarget: string | null;
  authorizedMode: ScanMode | null; allowedHosts: { hostname: string; includeSubdomains: boolean }[];
  excludedPaths: string[]; scopeId: string | null; contextId: string | null; rejectionReason: string | null; limitations: string[];
}
export const findingSchema = z.object({
  id: z.string().uuid(), engine: z.literal('engine2'), source: z.literal('zap'), zapPluginId: z.string().regex(/^\d+$/),
  title: z.string(), description: z.string(), severity: z.enum(['informational', 'low', 'medium', 'high', 'critical']),
  confidence: z.enum(['low', 'medium', 'high']), cweId: z.string().regex(/^CWE-\d+$/).nullable(),
  owasp: z.array(z.string()), affectedEndpoint: z.string(), evidence: z.array(z.object({ location: z.string(), observation: z.string() })),
  remediation: z.string(), references: z.array(z.string()), detectedAt: z.iso.datetime(),
});
export type Engine2Finding = z.infer<typeof findingSchema>;
export type SeverityCounts = Record<Engine2Finding['severity'], number>;
export interface SpiderScanResult {
  status: ScanStatus; errors: Engine2Error[]; scanId: string | null; discoveredUrls: string[];
  endpointCount: number; durationMs: number; exclusions: { url: string; reason: string }[]; limitations: string[];
}
export interface PassiveScanResult {
  status: ScanStatus; errors: Engine2Error[]; analysedMessages: number | null; pendingRecords: number | null;
  findings: Engine2Finding[]; counts: SeverityCounts; durationMs: number; limitations: string[];
}
export interface ActiveScanResult {
  status: ScanStatus; errors: Engine2Error[]; scanIds: string[]; policy: string | null; testedEndpoints: string[];
  findings: Engine2Finding[]; durationMs: number; limitations: string[];
}
export interface Engine2ScanResult {
  engine: 'engine2'; schemaVersion: '1.0'; jobId: string | null; status: ScanStatus; errors: Engine2Error[];
  scope: ScopeValidationResult; spider: SpiderScanResult; passive: PassiveScanResult; active: ActiveScanResult;
  findings: Engine2Finding[]; counts: SeverityCounts; durationMs: number; limitations: string[];
}
export interface ActivePolicy { name: string; ruleIds: string[]; strength: 'LOW' | 'MEDIUM'; threshold: 'MEDIUM' | 'HIGH'; }
export interface Engine2Config {
  enabled: boolean; activeEnabled: boolean; grants: AuthorizationGrant[]; policies: ActivePolicy[];
  totalTimeoutMs: number; startupTimeoutMs: number; spiderTimeoutMs: number; passiveTimeoutMs: number; activeTimeoutMs: number;
  apiTimeoutMs: number; requestTimeoutMs: number; pollIntervalMs: number; requestIntervalMs: number;
  maxRequests: number; maxResponseBytes: number; maxRequestBytes: number; maxDepth: number; maxChildren: number;
  maxEndpoints: number; maxActiveEndpoints: number; maxFindings: number; maxConcurrentScans: number;
  zapImage: string; gatewayImage: string; labNetwork: string; labTargetContainer: string;
}
