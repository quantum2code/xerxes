import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { redact, safeUrl } from '../../../shared/security/redaction.js';
import { owaspForCwe } from '../../../modules/web-security/reporting/classify.js';
import type { ApprovedScope } from '../scope/validator.js';
import { findingSchema, type Engine2Finding, type SeverityCounts } from '../types.js';

const scalar = z.union([z.string(), z.number()]);
export const alertSchema = z.object({
  id: scalar.refine((id) => /^\d{1,20}$/.test(String(id))).optional(), pluginId: scalar, alert: z.string().optional(), name: z.string().optional(), url: z.string().max(8192),
  risk: scalar.optional(), riskcode: scalar.optional(), confidence: scalar, cweid: scalar.optional(), sourceid: scalar,
  description: z.string().max(65536).default(''), solution: z.string().max(65536).default(''), reference: z.string().max(65536).default(''),
  evidence: z.string().max(5242880).default(''), param: z.string().max(4096).default(''), method: z.string().max(32).default(''),
});
const text = (value: string, limit = 2048) => redact(value).slice(0, limit);
export function counts(findings: Engine2Finding[] = []): SeverityCounts {
  const result = { informational: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const finding of findings) result[finding.severity]++;
  return result;
}
export function normalizeAlerts(raw: unknown[], scope: ApprovedScope, scanType: 'passive' | 'active') {
  const findings: Engine2Finding[] = []; const keys = new Set<string>();
  let invalid = 0; let excluded = 0;
  for (const value of raw) {
    const parsed = alertSchema.safeParse(value);
    if (!parsed.success) { invalid++; continue; }
    const alert = parsed.data;
    // ZAP source IDs: active=1, passive=3. Never conflate histories/modes.
    if (Number(alert.sourceid) !== (scanType === 'active' ? 1 : 3)) continue;
    if (!scope.includes(alert.url).allowed) { excluded++; continue; }
    const riskInput = alert.riskcode ?? alert.risk;
    const risk = /^\d+$/.test(String(riskInput)) ? Number(riskInput) : ['informational', 'low', 'medium', 'high'].indexOf(String(riskInput).toLowerCase());
    const confidence = /^\d+$/.test(String(alert.confidence)) ? Number(alert.confidence) : ['false positive', 'low', 'medium', 'high', 'confirmed'].indexOf(String(alert.confidence).toLowerCase());
    if (confidence === 0) continue;
    if (![0, 1, 2, 3].includes(risk) || ![1, 2, 3, 4].includes(confidence) || !/^\d+$/.test(String(alert.pluginId))) { invalid++; continue; }
    const key = JSON.stringify([alert.pluginId, new URL(alert.url).href, alert.param, alert.method]);
    if (keys.has(key)) continue; keys.add(key);
    const cwe = /^\d+$/.test(String(alert.cweid)) && Number(alert.cweid) > 0 ? `CWE-${alert.cweid}` : null;
    const references = new Set<string>([`https://www.zaproxy.org/docs/alerts/${alert.pluginId}/`]);
    for (const ref of alert.reference.match(/https?:\/\/[^\s<>"']+/g) ?? []) {
      try { const url = new URL(ref); if (!url.username && !url.password && references.size < 16) references.add(safeUrl(url.href)); } catch { /* Malformed references are not invented. */ }
    }
    const parameter = /^[a-zA-Z_][\w.-]{0,63}$/.test(alert.param) ? alert.param : '[omitted]';
    findings.push(findingSchema.parse({
      id: randomUUID(), engine: 'engine2', source: 'zap', scanType, zapPluginId: String(alert.pluginId), zapAlertId: alert.id === undefined ? null : String(alert.id),
      title: text(alert.alert ?? alert.name ?? 'ZAP security alert', 512), description: text(alert.description || 'Condition reported by the referenced ZAP rule; no independent exploit confirmation is implied.'),
      severity: ['informational', 'low', 'medium', 'high'][risk], confidence: confidence === 1 ? 'low' : confidence === 2 ? 'medium' : 'high',
      cweId: cwe, owasp: cwe ? owaspForCwe(cwe) : [], affectedEndpoint: safeUrl(alert.url),
      evidence: [{ location: `ZAP alert ${alert.id ?? '[unavailable]'}; rule ${alert.pluginId}; parameter ${parameter}`,
        observation: `Method ${['GET', 'HEAD', 'POST', 'OPTIONS'].includes(alert.method) ? alert.method : '[not supplied]'}; ZAP supplied ${Buffer.byteLength(alert.evidence)} evidence bytes. Raw match, request payload, cookies and otherInfo redacted; reproduce using the rule and endpoint.` }],
      remediation: text(alert.solution || 'Follow the remediation guidance in the referenced ZAP rule documentation.'), references: [...references], detectedAt: new Date().toISOString(),
    }));
  }
  return { findings, invalid, excluded };
}
