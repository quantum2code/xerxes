import { z } from 'zod';
import { setTimeout as delay } from 'node:timers/promises';
import type { ApprovedScope } from '../scope/validator.js';
import { assertJob, type ZapJob } from '../zap/job.js';
import { Engine2Failure, elapsed, scanError } from '../errors.js';
import { counts, normalizeAlerts } from '../reporting/normalize.js';
import { passiveAlerts } from '../zap/alerts.js';
import { countSchema } from '../zap/client.js';
import type { PassiveScanResult } from '../types.js';

export function emptyPassive(): PassiveScanResult { return { status: 'skipped', errors: [], analysedMessages: null, observedMessages: null, pendingRecords: null, findings: [], counts: counts(), durationMs: 0, limitations: [] }; }
async function configureRules(job: ZapJob, scope: ApprovedScope, signal: AbortSignal): Promise<void> {
  assertJob(job, scope, true);
  if (job.passiveConfigured) return;
  await job.client.action('pscan', 'setEnabled', { enabled: 'true' }, signal);
  await job.client.action('pscan', 'setScanOnlyInScope', { onlyInScope: 'true' }, signal);
  if (job.config.passiveRuleIds.length) {
    await job.client.action('pscan', 'disableAllScanners', {}, signal);
    await job.client.action('pscan', 'enableScanners', { ids: job.config.passiveRuleIds.join(',') }, signal);
  }
  job.passiveConfigured = true;
}
export async function configurePassive(job: ZapJob, scope: ApprovedScope, signal: AbortSignal): Promise<void> {
  await job.exclusive(signal, () => configureRules(job, scope, signal));
}
export async function scanPassive(job: ZapJob, scope: ApprovedScope, parent: AbortSignal = new AbortController().signal): Promise<PassiveScanResult> {
  const result = emptyPassive(); const start = performance.now(); const signal = AbortSignal.any([parent, AbortSignal.timeout(job.config.passiveTimeoutMs)]);
  try { await job.exclusive(signal, async () => {
    assertJob(job, scope, true); await configureRules(job, scope, signal);
    try {
      while (true) {
        result.pendingRecords = (await job.client.call('pscan', 'view', 'recordsToScan', {}, z.object({ recordsToScan: countSchema }), signal)).recordsToScan;
        if (result.pendingRecords === 0) break;
        await delay(job.config.pollIntervalMs, undefined, { signal });
      }
      result.status = 'completed';
    } catch (error) { result.status = 'partial'; result.errors.push(scanError('passive', error, signal)); }
    const collection = AbortSignal.timeout(job.config.apiTimeoutMs * 3);
    try {
      result.observedMessages = (await job.client.call('core', 'view', 'numberOfMessages', {}, z.object({ numberOfMessages: countSchema }), collection)).numberOfMessages;
      if (result.observedMessages === 0) { result.status = 'partial'; result.limitations.push('No HTTP messages available for passive assessment'); }
    } catch (error) { result.status = 'partial'; result.errors.push(scanError('passive', error)); }
    const page = await passiveAlerts(job, collection);
    result.errors.push(...page.errors);
    const normalized = normalizeAlerts(page.alerts, scope, 'passive'); result.findings = normalized.findings;
    if (page.truncated || normalized.invalid || normalized.excluded) { result.status = 'partial'; result.limitations.push('Alerts were truncated, malformed or excluded by scope filtering'); }
    result.limitations.push('Passive queue completion is not exploit confirmation. Exact analysed-message count is unavailable; observedMessages is total job history, not a fabricated processing count.', 'Raw matched evidence is redacted; plugin IDs, endpoints, descriptions, solutions and reference links are preserved.');
  }); } catch (error) {
    result.errors.push(scanError('passive', error, signal)); result.status = result.findings.length ? 'partial' : error instanceof Engine2Failure ? 'blocked' : signal.aborted ? 'cancelled' : 'failed';
  }
  result.counts = counts(result.findings); result.durationMs = elapsed(start); return result;
}
