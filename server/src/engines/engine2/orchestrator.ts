import { ScopeValidator } from './scope/validator.js';
import { createDockerJobFactory } from './zap/docker.js';
import { verifyLab } from './zap/lab.js';
import type { JobFactory, ZapJob } from './zap/job.js';
import { emptyScope } from './scope/validator.js';
import { configurePassive, emptyPassive, scanPassive } from './passive/scanner.js';
import { emptySpider, scanSpider } from './spider/spider.js';
import { emptyActive, scanActive } from './active/scanner.js';
import { counts } from './reporting/normalize.js';
import { Engine2Failure, elapsed, scanError } from './errors.js';
import { loadEngine2Config } from './config.js';
import type { Engine2Config, Engine2ScanResult } from './types.js';

export interface Engine2Options { validator?: ScopeValidator; jobs?: JobFactory; }
export class Engine2 {
  private running = 0;
  private readonly validator: ScopeValidator;
  private readonly jobs: JobFactory;
  constructor(private readonly config: Engine2Config = loadEngine2Config(), options: Engine2Options = {}) {
    this.validator = options.validator ?? new ScopeValidator(config, undefined, (signal) => verifyLab(config, undefined, signal));
    this.jobs = options.jobs ?? createDockerJobFactory(config);
  }
  async scan(input: unknown, cancellation?: AbortSignal): Promise<Engine2ScanResult> {
    const started = performance.now();
    const result: Engine2ScanResult = { engine: 'engine2', schemaVersion: '1.0', jobId: null, status: 'skipped', errors: [],
      scope: emptyScope(), spider: emptySpider(), passive: emptyPassive(), active: emptyActive(), findings: [], counts: counts(), durationMs: 0,
      limitations: ['ZAP findings are not a phishing verdict or unified risk score. Zero alerts do not prove a secure application.',
        'Traditional crawling only; anonymous traffic with no credential/cookie forwarding. No browser, custom exploit payloads or reputation lookups.'] };
    const finish = () => {
      result.findings = [...result.passive.findings, ...result.active.findings].slice(0, this.config.maxFindings);
      if (result.passive.findings.length + result.active.findings.length > this.config.maxFindings) { result.status = 'partial'; result.limitations.push('Combined finding limit reached'); }
      result.counts = counts(result.findings);
      result.errors.push(...result.scope.errors, ...result.spider.errors, ...result.passive.errors, ...result.active.errors);
      result.limitations = [...new Set([...result.limitations, ...result.scope.limitations, ...result.spider.limitations, ...result.passive.limitations, ...result.active.limitations])];
      result.durationMs = elapsed(started); return result;
    };
    if (!this.config.enabled || input === undefined) { result.limitations.push(this.config.enabled ? 'Engine 2 was not requested' : 'Engine 2 is disabled; no target or management requests were made'); return finish(); }
    if (this.running >= this.config.maxConcurrentScans) {
      result.status = 'blocked'; result.errors.push({ stage: 'orchestrator', code: 'CAPACITY_LIMIT', message: 'Engine 2 scan capacity reached' }); return finish();
    }
    this.running++;
    let job: ZapJob | null = null;
    const total = AbortSignal.any([AbortSignal.timeout(this.config.totalTimeoutMs), ...(cancellation ? [cancellation] : [])]);
    try {
      const approval = await this.validator.validate(input, total); result.scope = approval.result;
      if (!approval.scope) { result.status = approval.result.status; return finish(); }
      const scope = approval.scope;
      const signal = AbortSignal.any([total, AbortSignal.timeout(Math.max(1, Math.min(this.config.totalTimeoutMs, scope.expiresAt - Date.now())))]);
      signal.throwIfAborted(); job = await this.jobs(scope, signal); result.jobId = job.id; result.scope.contextId = job.contextId;
      await configurePassive(job, scope, signal); // Enable before the spider generates any traffic.
      result.spider = await scanSpider(job, scope, signal);
      // Read-only completion/collection gets a bounded cleanup budget even after cancellation.
      result.passive = await scanPassive(job, scope, signal.aborted ? AbortSignal.timeout(Math.min(this.config.passiveTimeoutMs, this.config.apiTimeoutMs * 2)) : signal);
      if (scope.request.mode === 'active') {
        if (!signal.aborted && result.spider.status === 'completed' && result.passive.status === 'completed') result.active = await scanActive(job, scope, job.endpoints(), signal);
        else result.active.limitations.push('Authorized active testing was not started because crawling/passive coverage was incomplete or cancelled');
      } else result.active.limitations.push('Active testing was not requested and was never started');
      result.status = result.spider.status === 'completed' && result.passive.status === 'completed' && (scope.request.mode === 'passive' || result.active.status === 'completed') ? 'completed' : 'partial';
      try {
        const stats = await job.statistics(AbortSignal.timeout(this.config.apiTimeoutMs));
        if (stats.denied || stats.failures || stats.exhausted || !stats.forwarded) { result.status = 'partial'; result.limitations.push('Gateway recorded policy denials, upstream failures, no traffic or exhausted request budget; coverage is incomplete'); }
      } catch (error) { result.status = 'partial'; result.errors.push(scanError('orchestrator', error)); result.limitations.push('Gateway statistics unavailable; complete coverage cannot be established'); }
    } catch (error) {
      result.errors.push(scanError('orchestrator', error, total));
      result.status = error instanceof Engine2Failure && error.code === 'ZAP_UNAVAILABLE' ? 'unavailable' : job ? 'partial' : total.aborted ? 'cancelled' : 'failed';
    } finally {
      if (job) try { await job.close(); } catch (error) { result.status = 'partial'; result.errors.push(scanError('orchestrator', error)); }
      this.running--;
    }
    return finish();
  }
}
