import { Resolver as NodeResolver } from 'node:dns/promises';
import { Semaphore } from '../../../shared/network/limits.js';
import { recordTypes, type RecordType, type UrlAnalysisConfig, type DnsResult } from '../types.js';
import { AnalysisFailure, structuredError } from '../errors.js';
import { applyRecords } from './records.js';

export type RecordQuery = (type: RecordType, hostname: string, signal: AbortSignal) => Promise<unknown[]>;
export function createNodeQuery(timeoutMs: number): RecordQuery {
  return async (type, hostname, signal) => {
    signal.throwIfAborted();
    // One cancellable resolver per operation: timing out TXT cannot discard an ongoing A query.
    const resolver = new NodeResolver({ timeout: timeoutMs, tries: 1 });
    const cancel = () => resolver.cancel();
    signal.addEventListener('abort', cancel, { once: true });
    try {
      switch (type) {
        case 'A': return await resolver.resolve4(hostname, { ttl: true });
        case 'AAAA': return await resolver.resolve6(hostname, { ttl: true });
        case 'CNAME': return await resolver.resolveCname(hostname);
        case 'MX': return await resolver.resolveMx(hostname);
        case 'NS': return await resolver.resolveNs(hostname);
        case 'TXT': return await resolver.resolveTxt(hostname);
      }
    } finally { signal.removeEventListener('abort', cancel); resolver.cancel(); }
  };
}
export function emptyDns(): DnsResult {
  return { status: 'skipped', durationMs: 0, a: [], aaaa: [], cname: [], mx: [], ns: [], txt: [], errors: [],
    queries: Object.fromEntries(recordTypes.map((type) => [type, { status: 'skipped', durationMs: 0, truncated: false }])) as DnsResult['queries'] };
}
export class DnsAnalyzer {
  private readonly semaphore: Semaphore;
  private readonly query: RecordQuery;
  constructor(private readonly config: UrlAnalysisConfig, query?: RecordQuery) {
    this.semaphore = new Semaphore(config.dnsConcurrency);
    this.query = query ?? createNodeQuery(config.dnsTimeoutMs);
  }
  private async execute(type: RecordType, hostname: string, parent: AbortSignal): Promise<unknown[]> {
    const signal = AbortSignal.any([parent, AbortSignal.timeout(this.config.dnsTimeoutMs)]);
    try { return await this.semaphore.run(signal, async () => {
      const raw = await this.query(type, hostname, signal);
      signal.throwIfAborted();
      return raw;
    }); }
    catch (error) {
      if (signal.aborted) throw signal.reason;
      throw error;
    }
  }
  async analyze(hostname: string, signal: AbortSignal): Promise<DnsResult> {
    const started = Date.now();
    const result = emptyDns();
    await Promise.all(recordTypes.map(async (type) => {
      const start = Date.now();
      try {
        const raw = await this.execute(type, hostname, signal);
        const truncated = applyRecords(result, type, raw, this.config);
        result.queries[type] = { status: raw.length ? 'completed' : 'absent', durationMs: Date.now() - start, truncated };
      } catch (error) {
        const timedOut = error instanceof Error && error.name === 'TimeoutError';
        const observed = timedOut ? { stage: 'dns' as const, code: 'TIMEOUT', message: 'DNS query deadline exceeded', retryable: true } : structuredError('dns', error, signal);
        const recordError = { ...observed, recordType: type };
        result.errors.push(recordError);
        result.queries[type] = { status: observed.code === 'ENODATA' ? 'absent' : 'failed', durationMs: Date.now() - start, truncated: false, error: recordError };
      }
    }));
    const queries = Object.values(result.queries);
    const failures = queries.filter((q) => q.status === 'failed').length;
    result.status = failures === queries.length ? 'failed' : failures || queries.some((q) => q.truncated) ? 'partial' : 'completed';
    result.durationMs = Date.now() - started;
    // Deterministic record-type error order, independent of query completion timing.
    result.errors.sort((a, b) => recordTypes.indexOf(a.recordType!) - recordTypes.indexOf(b.recordType!));
    return result;
  }
  /** Fresh address queries for each connection; incomplete/temporary answers fail closed. Never uses truncated reporting data. */
  async connectionAddresses(hostname: string, signal: AbortSignal): Promise<{ address: string; family: number }[]> {
    const outcomes = await Promise.allSettled((['A', 'AAAA'] as const).map(async (type) => {
      const raw = await this.execute(type, hostname, signal);
      const temporary = emptyDns();
      // Validate all records, not the report's bounded subset, before allowing network access.
      applyRecords(temporary, type, raw, { ...this.config, maxDnsRecords: Number.MAX_SAFE_INTEGER });
      return (type === 'A' ? temporary.a : temporary.aaaa).map(({ address }) => ({ address, family: type === 'A' ? 4 : 6 }));
    }));
    const addresses: { address: string; family: number }[] = [];
    for (const outcome of outcomes) {
      if (outcome.status === 'fulfilled') addresses.push(...outcome.value);
      else {
        const error = structuredError('dns', outcome.reason, signal);
        if (!['ENODATA', 'ENOTFOUND'].includes(error.code)) throw outcome.reason;
        // NXDOMAIN on one family with a successful answer on another is inconsistent; reject below.
        if (error.code === 'ENOTFOUND' && outcomes.some((o) => o.status === 'fulfilled' && o.value.length)) throw new AnalysisFailure('INCONSISTENT_DNS', 'Inconsistent DNS address responses');
      }
    }
    if (!addresses.length) throw new AnalysisFailure('NO_ADDRESSES', 'No usable DNS address records');
    return addresses;
  }
}
