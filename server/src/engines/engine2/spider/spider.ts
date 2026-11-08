import { z } from 'zod';
import { setTimeout as delay } from 'node:timers/promises';
import { safeUrl } from '../../../shared/security/redaction.js';
import { Engine2Failure, elapsed, scanError } from '../errors.js';
import type { SpiderScanResult } from '../types.js';
import { ApprovedScope } from '../scope/validator.js';
import { assertJob, type ZapJob } from '../zap/job.js';
import { idSchema, progressSchema } from '../zap/client.js';

export function emptySpider(): SpiderScanResult { return { status: 'skipped', errors: [], scanId: null, discoveredUrls: [], endpointCount: 0, durationMs: 0, exclusions: [], limitations: [] }; }
export async function scanSpider(job: ZapJob, scope: ApprovedScope, parent: AbortSignal = new AbortController().signal): Promise<SpiderScanResult> {
  const result = emptySpider(); const start = performance.now();
  const signal = AbortSignal.any([parent, AbortSignal.timeout(job.config.spiderTimeoutMs)]);
  try { await job.exclusive(signal, async () => {
    let mayBeRunning = false;
    try {
    assertJob(job, scope); await job.enterPhase('crawl', signal);
    for (const [name, params] of [
      ['setOptionMaxDepth', { Integer: String(job.config.maxDepth) }],
      ['setOptionMaxChildren', { Integer: String(job.config.maxChildren) }],
      ['setOptionThreadCount', { Integer: '1' }],
      ['setOptionProcessForm', { Boolean: 'false' }], ['setOptionPostForm', { Boolean: 'false' }],
      ['setOptionParseRobotsTxt', { Boolean: 'false' }], ['setOptionParseSitemapXml', { Boolean: 'false' }],
    ] as const) await job.client.action('spider', name, params, signal);
    // Generated ZAP option setters use capitalized Integer/Boolean parameter names.
    mayBeRunning = true;
    const started = await job.client.call('spider', 'action', 'scan', { url: scope.target, recurse: 'true', contextName: `engine2-${scope.id}`, subtreeOnly: 'true' }, z.object({ scan: idSchema }), signal);
    result.scanId = started.scan;
    try {
      while ((await job.client.call('spider', 'view', 'status', { scanId: result.scanId }, progressSchema, signal)).status < 100) await delay(job.config.pollIntervalMs, undefined, { signal });
      result.status = 'completed'; mayBeRunning = false;
    } catch (error) { result.status = 'partial'; result.errors.push(scanError('spider', error, signal)); }
    if (result.status !== 'completed') {
      try { await job.client.action('spider', 'stop', { scanId: result.scanId }, AbortSignal.timeout(job.config.apiTimeoutMs)); mayBeRunning = false; }
      catch (error) { result.errors.push(scanError('spider', error)); }
    }
    // Use a separate cleanup budget: cancelled crawling must still return discovered partial endpoints.
    const collected = await job.client.call('spider', 'view', 'results', { scanId: result.scanId }, z.object({ results: z.array(z.string().max(8192)).max(10000) }), AbortSignal.timeout(job.config.apiTimeoutMs));
    const endpoints = new Set<string>(); const visible = new Set<string>();
    for (const raw of collected.results) {
      const decision = scope.includes(raw);
      if (!decision.allowed) { if (result.exclusions.length < job.config.maxEndpoints) result.exclusions.push({ url: safeUrl(raw), reason: decision.reason! }); continue; }
      if (endpoints.size >= job.config.maxEndpoints) { result.status = 'partial'; result.limitations.push('Endpoint reporting/crawl resource limit reached'); break; }
      endpoints.add(new URL(raw).href); visible.add(safeUrl(raw));
    }
    job.recordEndpoints([...endpoints]); result.discoveredUrls = [...visible]; result.endpointCount = result.discoveredUrls.length;
    if (!endpoints.size) { result.status = 'partial'; result.limitations.push('No approved endpoint was discovered; no complete coverage can be claimed'); }
    result.limitations.push('Traditional ZAP Spider only; no browser or Ajax Spider. Forms and robots/sitemap probes are disabled; GET can still change application state.');
    } finally {
      try { await job.enterPhase('idle', AbortSignal.timeout(job.config.apiTimeoutMs)); } catch { result.limitations.push('Gateway reset failed; close this job before reuse'); result.status = 'partial'; }
      if (mayBeRunning) {
        try { await job.client.action('spider', 'stopAllScans', {}, AbortSignal.timeout(job.config.apiTimeoutMs)); }
        catch { await job.close(); }
      }
    }
  }); } catch (error) {
    result.errors.push(scanError('spider', error, signal)); result.status = result.scanId ? 'partial' : error instanceof Engine2Failure ? 'blocked' : signal.aborted ? 'cancelled' : 'failed';
  }
  result.durationMs = elapsed(start); return result;
}
