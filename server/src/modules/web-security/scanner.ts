import { setTimeout as delay } from 'node:timers/promises';
import { defaultChecks } from './checks/index.js';
import { baseUrl, elements } from './checks/helpers.js';
import { authorize, parseTarget, PolicyError } from './network/policy.js';
import { createTransport, type Transport } from './network/transport.js';
import { countSeverities, findingKey, normalize, safeUrl } from './reporting/normalize.js';
import type { Check, Finding, FindingInput, Page, ScannerConfig, ScanRequest, ScanResult } from './types.js';

export interface BackendOutput {
  status: ScanResult['backend']['zap'];
  findings: FindingInput[];
  limitations: string[];
}
export type ZapBackend = (request: ScanRequest, pages: Page[], budget: number, signal: AbortSignal) => Promise<BackendOutput>;
export interface ScannerOptions { transport?: Transport; checks?: readonly Check[]; zap?: ZapBackend; }

export class WebSecurityScanner {
  private running = 0;
  private readonly transport: Transport;
  private readonly checks: readonly Check[];
  constructor(private readonly config: ScannerConfig, private readonly options: ScannerOptions = {}) {
    this.transport = options.transport ?? createTransport(config);
    this.checks = options.checks ?? defaultChecks;
    if (new Set(this.checks.map((c) => c.id)).size !== this.checks.length) throw new Error('Duplicate check IDs');
  }

  async scan(input: unknown, cancellation?: AbortSignal): Promise<ScanResult> {
    const started = Date.now();
    const request = input && typeof input === 'object' ? input as ScanRequest : { url: '' };
    const result: ScanResult = {
      schemaVersion: '1.0', targetUrl: typeof request.url === 'string' ? safeUrl(request.url) : '[invalid URL]',
      mode: request.mode === 'active' ? 'active' : 'passive', status: 'completed', durationMs: 0,
      checksExecuted: [], checksSkipped: [], counts: countSeverities([]), findings: [],
      backend: { native: 'available', zap: this.config.zap.enabled ? 'unavailable' : 'disabled' },
      coverageLimitations: [
        'No scripts executed, forms submitted, authentication attempted, or hidden paths probed by native checks.',
        'Only bounded same-origin HTTP responses are assessed; no finding does not imply a secure website.',
        'CORS origin reflection and credentialed reads are not tested. Dependency advisory coverage is limited to recognized jQuery banners.',
        'Browser behavior, CSS imports, dynamically generated content, and actual exploitability are not verified.',
        'HTML structure inspection is capped at the first 256 KiB and 10,000 tag starts per response; reports at 500 findings.',
      ],
    };
    const finish = () => {
      result.counts = countSeverities(result.findings);
      result.durationMs = Date.now() - started;
      for (const check of this.checks) if (!result.checksExecuted.includes(check.id) && !result.checksSkipped.some((s) => s.checkId === check.id)) {
        result.checksSkipped.push({ checkId: check.id, reason: 'No assessable response received' });
      }
      return result;
    };
    let target: URL;
    let authorizationDeadline: number;
    try { target = parseTarget(request.url); authorizationDeadline = authorize(request, target, this.config); }
    catch { result.status = 'blocked'; result.coverageLimitations.push('Invalid target, mode, or missing/expired target authorization'); return finish(); }
    if (this.running >= this.config.maxConcurrentScans) {
      result.status = 'blocked'; result.coverageLimitations.push('Scanner concurrency capacity reached; retry later'); return finish();
    }
    this.running++;
    const signal = AbortSignal.any([AbortSignal.timeout(Math.max(1, Math.min(this.config.scanTimeoutMs, authorizationDeadline - Date.now()))), ...(cancellation ? [cancellation] : [])]);
    const queue: { url: URL; depth: number; redirects: number }[] = [{ url: target, depth: 0, redirects: 0 }];
    const visited = new Set<string>();
    const keys = new Set<string>();
    const pages: Page[] = [];
    const add = (finding: FindingInput) => {
      if (result.findings.length >= 500) { result.status = 'partial'; return; }
      const key = findingKey(finding);
      if (!keys.has(key)) { const normalized = normalize(finding); result.findings.push(normalized); keys.add(key); }
    };
    let requests = 0;
    let lastRequest = 0;
    try {
      while (queue.length && requests < this.config.maxRequests && !signal.aborted) {
        const item = queue.shift()!;
        if (visited.has(item.url.href)) continue;
        visited.add(item.url.href);
        try {
          const wait = this.config.requestIntervalMs - (Date.now() - lastRequest);
          if (wait > 0) await delay(wait, undefined, { signal });
          signal.throwIfAborted();
          requests++; lastRequest = Date.now();
          const page = await this.transport(item.url, signal);
          // Even trusted test/integration transports must not silently follow redirects.
          if (page.url !== item.url.href || !Number.isInteger(page.status) || page.status < 100 || page.status > 599 ||
            typeof page.body !== 'string' || !page.headers || typeof page.headers !== 'object') throw new Error('Malformed response');
          pages.push(page);
          for (const check of this.checks) {
            try {
              const findings = check.run(page);
              findings.forEach(add);
              if (!result.checksExecuted.includes(check.id)) result.checksExecuted.push(check.id);
            } catch {
              result.status = 'partial';
              result.checksSkipped.push({ checkId: check.id, reason: 'Check failed on a response; output is incomplete' });
            }
          }
          if (page.status >= 300 && page.status < 400) {
            const location = Object.entries(page.headers).find(([name]) => name.toLowerCase() === 'location')?.[1];
            if (typeof location === 'string') {
              const next = parseTarget(new URL(location, item.url).href);
              if (next.origin !== target.origin || item.redirects >= this.config.maxRedirects || visited.has(next.href)) throw new PolicyError('Redirect out of scope, looping, or over budget');
              queue.unshift({ ...item, url: next, redirects: item.redirects + 1 });
            }
            continue;
          }
          if (item.depth >= this.config.maxDepth) continue;
          const base = baseUrl(page);
          for (const element of elements(page)) {
            const reference = element.tag === 'script' ? element.attrs.src : element.tag === 'a' ? element.attrs.href : undefined;
            if (!reference || reference.startsWith('#')) continue;
            try {
              const next = new URL(reference, base); next.hash = '';
              parseTarget(next.href);
              if (next.origin !== target.origin || next.search || /(?:logout|signout|delete|remove|unsubscribe)/i.test(next.pathname)) continue;
              if (!visited.has(next.href) && !queue.some((q) => q.url.href === next.href) && queue.length < this.config.maxRequests) queue.push({ url: next, depth: item.depth + 1, redirects: 0 });
            } catch { /* Invalid or unsafe discovered links are not followed. */ }
          }
        } catch (error) {
          result.status = pages.length ? 'partial' : error instanceof PolicyError ? 'blocked' : 'failed';
          result.coverageLimitations.push(error instanceof PolicyError ? 'A request or redirect was blocked by network/scope policy' : 'A request failed, exceeded a limit, or returned an unsupported response');
        }
      }
      if (queue.length || signal.aborted) {
        result.status = pages.length ? 'partial' : 'failed';
        result.coverageLimitations.push('Scan deadline, cancellation, or request budget prevented complete traversal');
      }
      if (this.config.zap.enabled && pages.length && !signal.aborted) {
        if (this.options.zap) {
          try {
            const zap = await this.options.zap(request, pages, this.config.maxRequests - requests, signal);
            result.backend.zap = zap.status; zap.findings.forEach(add);
            result.coverageLimitations.push(...zap.limitations);
            if (zap.status === 'completed') result.checksExecuted.push('zap');
            else { result.status = 'partial'; result.checksSkipped.push({ checkId: 'zap', reason: `Optional backend ${zap.status}` }); }
          } catch {
            result.backend.zap = 'failed'; result.status = 'partial'; result.checksSkipped.push({ checkId: 'zap', reason: 'Optional backend failed' });
          }
        } else { result.status = 'partial'; result.checksSkipped.push({ checkId: 'zap', reason: 'Optional backend unavailable' }); }
      } else {
        result.checksSkipped.push({ checkId: 'zap', reason: this.config.zap.enabled ? 'No response, deadline, or cancellation' : 'Optional backend disabled' });
      }
      if (request.mode === 'active' && result.backend.zap !== 'completed') {
        result.status = pages.length ? 'partial' : result.status;
        result.coverageLimitations.push('Requested active assessment did not complete; native findings are passive only');
      }
    } finally { this.running--; }
    return finish();
  }
}
