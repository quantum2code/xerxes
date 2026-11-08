import { createHash, randomUUID } from 'node:crypto';
import { severities, type Finding, type FindingInput, type Severity } from '../types.js';
import { redact, safeUrl } from '../../../shared/security/redaction.js';
export { redact, safeUrl } from '../../../shared/security/redaction.js';

export function normalize(input: FindingInput, detectedAt = new Date().toISOString()): Finding {
  if (!severities.includes(input.severity) || !['low', 'medium', 'high'].includes(input.confidence) || !input.evidence.length ||
    (input.source !== undefined && !['native', 'zap'].includes(input.source)) ||
    input.evidence.some((e) => typeof e.location !== 'string' || !e.location.trim() || typeof e.observation !== 'string' || !e.observation.trim())) {
    throw new Error('Invalid finding severity, confidence, or evidence');
  }
  const clean = (value: string) => redact(value).slice(0, 1024);
  return {
    id: randomUUID(), detectedAt, severity: input.severity, confidence: input.confidence,
    checkId: clean(input.checkId), title: clean(input.title), description: clean(input.description),
    affectedUrl: safeUrl(input.affectedUrl), remediation: clean(input.remediation), source: input.source ?? 'native',
    evidence: input.evidence.slice(0, 5).map((e) => ({ location: clean(e.location), observation: clean(e.observation) })),
    cwe: (input.cwe ?? []).filter((id) => /^CWE-\d+$/.test(id)),
    owasp: (input.owasp ?? []).filter((id) => /^A(?:0[1-9]|10):2021$/.test(id)),
    cves: (input.cves ?? []).filter((id) => /^CVE-\d{4}-\d{4,}$/.test(id)),
  };
}
export function findingKey(input: FindingInput): string {
  // Deduplicate on original location without exposing it or any secret values.
  return createHash('sha256').update(JSON.stringify([input.source ?? 'native', input.checkId, input.title, input.affectedUrl, input.evidence])).digest('hex');
}
export function countSeverities(findings: Finding[]): Record<Severity, number> {
  const counts = Object.fromEntries(severities.map((s) => [s, 0])) as Record<Severity, number>;
  for (const finding of findings) counts[finding.severity]++;
  return counts;
}
