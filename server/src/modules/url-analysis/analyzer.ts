import { isIP } from 'node:net';
import { DnsAnalyzer, emptyDns, type RecordQuery } from './dns/resolver.js';
import { HttpAnalyzer, emptyHttp } from './http/client.js';
import { createHttpTransport, type HttpTransport } from './http/transport.js';
import { parseUrl } from './url/parser.js';
import { extractFeatures } from './url/features.js';
import { assertNetworkTarget } from './security/ip-validation.js';
import { structuredError } from './errors.js';
import type { UrlAnalysisResult, UrlAnalysisConfig } from './types.js';
import { loadUrlAnalysisConfig } from './config.js';

export interface AnalyzerOptions { query?: RecordQuery; transport?: HttpTransport; }
export class UrlAnalyzer {
  private running = 0;
  private readonly dns: DnsAnalyzer;
  private readonly http: HttpAnalyzer;
  constructor(private readonly config: UrlAnalysisConfig = loadUrlAnalysisConfig(), options: AnalyzerOptions = {}) {
    this.dns = new DnsAnalyzer(config, options.query);
    this.http = new HttpAnalyzer(config, options.transport ?? createHttpTransport(config, this.dns));
  }
  async analyze(input: unknown, cancellation?: AbortSignal): Promise<UrlAnalysisResult> {
    const started = performance.now();
    const result: UrlAnalysisResult = {
      module: 'urlAnalysis', schemaVersion: '1.0', status: 'completed', input: '[REDACTED INVALID URL]', durationMs: 0,
      url: null, features: null, dns: emptyDns(), http: emptyHttp(), errors: [], limitations: [
        'Features and network observations are not a phishing verdict, ownership proof, or risk score.',
        'Reports redact query values, fragments, credential-like paths, TXT contents and non-allowlisted HTTP headers. Report URLs are not fetch targets.',
        'HTTP completion means metadata headers received; response bodies are immediately closed, not downloaded or analyzed.',
        'DNSSEC, certificate analysis, reputation lookups, browser behavior, and vulnerability testing are outside Module 1.',
      ],
    };
    const finish = () => { result.durationMs = Math.round(performance.now() - started); return result; };
    let parsed: ReturnType<typeof parseUrl>;
    try {
      parsed = parseUrl(input, this.config.maxUrlLength);
      result.input = parsed.data.original; result.url = parsed.data; result.features = extractFeatures(parsed);
    } catch (error) { result.status = 'failed'; result.errors.push(structuredError('input', error)); return finish(); }
    try { assertNetworkTarget(parsed.target, this.config); }
    catch (error) { result.status = 'blocked'; result.http.status = 'blocked'; const detail = structuredError('http', error); result.errors.push(detail); result.http.errors.push(detail); return finish(); }
    if (this.running >= this.config.maxConcurrentAnalyses) {
      result.status = 'blocked'; result.errors.push({ stage: 'analysis', code: 'CAPACITY_LIMIT', message: 'Analyzer concurrency limit reached', retryable: true }); return finish();
    }
    this.running++;
    const signal = AbortSignal.any([AbortSignal.timeout(this.config.analysisTimeoutMs), ...(cancellation ? [cancellation] : [])]);
    try {
      // Metadata DNS and HTTP are independent; HTTP uses its own fresh address validation, not bounded report arrays.
      [result.dns, result.http] = await Promise.all([
        isIP(parsed.data.hostname) ? Promise.resolve(emptyDns()) : this.dns.analyze(parsed.data.hostname, signal),
        this.http.analyze(parsed.target, signal),
      ]);
      result.errors.push(...result.dns.errors, ...result.http.errors);
      result.status = result.http.status === 'blocked' ? 'blocked' :
        ['completed', 'skipped'].includes(result.dns.status) && result.http.status === 'completed' ? 'completed' : 'partial';
    } finally { this.running--; }
    return finish();
  }
}
