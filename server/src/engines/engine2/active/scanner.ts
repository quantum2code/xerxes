import { z } from 'zod';
import { setTimeout as delay } from 'node:timers/promises';
import { safeUrl } from '../../../shared/security/redaction.js';
import { ApprovedScope } from '../scope/validator.js';
import { assertJob, type ZapJob } from '../zap/job.js';
import { idSchema, progressSchema } from '../zap/client.js';
import { activeAlerts } from '../zap/alerts.js';
import { normalizeAlerts } from '../reporting/normalize.js';
import { Engine2Failure, elapsed, scanError } from '../errors.js';
import type { ActiveScanResult } from '../types.js';

export function emptyActive(): ActiveScanResult { return { status: 'skipped', errors: [], scanIds: [], policy: null, testedEndpoints: [], findings: [], durationMs: 0, limitations: [] }; }
export async function scanActive(job: ZapJob, scope: ApprovedScope, endpoints = job.endpoints(), parent: AbortSignal = new AbortController().signal): Promise<ActiveScanResult> {
  const result = emptyActive(); const start = performance.now(); const signal = AbortSignal.any([parent, AbortSignal.timeout(job.config.activeTimeoutMs)]);
  try { await job.exclusive(signal, async () => {
    let phaseEntered = false; let mayBeRunning = false;
    try {
    assertJob(job, scope);
    if (!job.config.activeEnabled || scope.request.mode !== 'active') throw new Engine2Failure('ACTIVE_NOT_AUTHORIZED', 'Active testing requires verified active scope and explicit enablement');
    const selected = job.config.policies.find((p) => p.name === scope.request.policy);
    if (!selected) throw new Engine2Failure('POLICY_UNAVAILABLE', 'Authorized policy is unavailable');
    // Validate the entire proposed endpoint list before starting any scan.
    for (const endpoint of endpoints) scope.assert(endpoint);
    const unique = [...new Set(endpoints.map((url) => new URL(url).href))];
    if (!unique.length) throw new Engine2Failure('NO_APPROVED_TRAFFIC', 'Active scanning needs discovered endpoints or an explicitly supplied authorized endpoint');
    result.policy = selected.name; await job.enterPhase('active', signal); phaseEntered = true;
    const policyName = `engine2-${scope.id}-${selected.name}`;
    await job.client.action('ascan', 'addScanPolicy', { scanPolicyName: policyName, attackStrength: selected.strength, alertThreshold: selected.threshold }, signal);
    await job.client.action('ascan', 'disableAllScanners', { scanPolicyName: policyName }, signal);
    await job.client.action('ascan', 'enableScanners', { scanPolicyName: policyName, ids: selected.ruleIds.join(',') }, signal);
    await job.client.action('ascan', 'setOptionThreadPerHost', { Integer: '1' }, signal);
    await job.client.action('ascan', 'setOptionDelayInMs', { Integer: String(job.config.requestIntervalMs) }, signal);
    result.status = 'completed';
    if (unique.length > job.config.maxActiveEndpoints) { result.status = 'partial'; result.limitations.push('Active endpoint limit reached; additional discovered endpoints were not tested'); }
    for (const endpoint of unique.slice(0, job.config.maxActiveEndpoints)) {
      scope.assert(endpoint); signal.throwIfAborted();
      if (!job.endpoints().includes(endpoint)) {
        // Standalone module use: populate this one approved GET in the isolated session, without custom crawling.
        await job.client.call('core', 'action', 'accessUrl', { url: endpoint, followRedirects: 'false' }, z.object({ accessUrl: z.array(z.unknown()).min(1).max(100) }), signal);
        job.recordEndpoints([endpoint]);
      }
      mayBeRunning = true;
      const scan = await job.client.call('ascan', 'action', 'scan', { url: endpoint, recurse: 'false', inScopeOnly: 'true', contextId: job.contextId, scanPolicyName: policyName }, z.object({ scan: idSchema }), signal);
      result.scanIds.push(scan.scan); result.testedEndpoints.push(safeUrl(endpoint));
      try {
        while ((await job.client.call('ascan', 'view', 'status', { scanId: scan.scan }, progressSchema, signal)).status < 100) await delay(job.config.pollIntervalMs, undefined, { signal });
        mayBeRunning = false;
      } catch (error) {
        result.status = 'partial'; result.errors.push(scanError('active', error, signal));
        try { await job.client.action('ascan', 'stop', { scanId: scan.scan }, AbortSignal.timeout(job.config.apiTimeoutMs)); mayBeRunning = false; }
        catch (stopError) { result.errors.push(scanError('active', stopError)); }
      }
      const raw = await activeAlerts(job, scan.scan, AbortSignal.timeout(job.config.apiTimeoutMs * 3));
      const normalized = normalizeAlerts(raw.alerts, scope, 'active');
      const remaining = job.config.maxFindings - result.findings.length;
      result.findings.push(...normalized.findings.slice(0, remaining));
      if (normalized.findings.length > remaining) { result.status = 'partial'; result.limitations.push('Active finding limit reached'); }
      if (raw.truncated || normalized.invalid || normalized.excluded) { result.status = 'partial'; result.limitations.push('Active alerts were truncated, malformed or excluded'); }
      if (signal.aborted) break;
    }
    result.limitations.push(`Only installed and explicitly selected ZAP rules (${selected.ruleIds.join(',')}) were used; not all OWASP classes are automatically detectable.`, 'No recursive active scan, browser, OAST or custom exploit payload engine. Passive findings cover the earlier captured traffic.');
    } finally {
      if (phaseEntered) try { await job.enterPhase('idle', AbortSignal.timeout(job.config.apiTimeoutMs)); } catch { result.limitations.push('Gateway reset failed; close this job before reuse'); result.status = 'partial'; }
      if (mayBeRunning) {
        try { await job.client.action('ascan', 'stopAllScans', {}, AbortSignal.timeout(job.config.apiTimeoutMs)); }
        catch { await job.close(); }
      }
    }
  }); } catch (error) {
    result.errors.push(scanError('active', error, signal)); result.status = result.scanIds.length ? 'partial' : error instanceof Engine2Failure ? 'blocked' : signal.aborted ? 'cancelled' : 'failed';
  }
  result.durationMs = elapsed(start); return result;
}
