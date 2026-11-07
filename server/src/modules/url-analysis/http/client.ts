import { MIMEType } from 'node:util';
import type { HttpResult, UrlAnalysisConfig } from '../types.js';
import { AnalysisFailure, structuredError } from '../errors.js';
import { parseUrl } from '../url/parser.js';
import { reportUrl } from '../url/normalize.js';
import { assertNetworkTarget } from '../security/ip-validation.js';
import type { HttpSnapshot, HttpTransport } from './transport.js';
import { crossesDomain, redirectStatuses } from './redirects.js';

export function emptyHttp(): HttpResult {
  return { status: 'skipped', statusCode: null, finalUrl: null, method: null, redirects: [], redirectCount: 0,
    requestCount: 0, responseTimeMs: 0, contentType: null, contentLength: null, headers: {}, errors: [] };
}
function header(response: HttpSnapshot, name: string): string | undefined {
  const value = response.headers[name];
  if (Array.isArray(value)) throw new AnalysisFailure('INVALID_HTTP_RESPONSE', 'Ambiguous metadata response headers');
  return value;
}
function metadata(response: HttpSnapshot): Pick<HttpResult, 'headers' | 'contentType' | 'contentLength'> {
  const selected: Record<string, string> = {};
  let contentType: string | null = null;
  const type = header(response, 'content-type');
  try { if (type) contentType = new MIMEType(type).essence; } catch { /* Malformed MIME type is not useful metadata. */ }
  const length = header(response, 'content-length');
  const contentLength = length && /^\d+$/.test(length) && Number.isSafeInteger(Number(length)) ? Number(length) : null;
  if (contentType) selected['content-type'] = contentType;
  if (contentLength !== null) selected['content-length'] = String(contentLength);
  const date = header(response, 'date');
  if (date && Number.isFinite(Date.parse(date))) selected.date = new Date(date).toUTCString();
  const allow = header(response, 'allow');
  if (allow && /^(?:GET|HEAD|POST|OPTIONS|PUT|DELETE|PATCH)(?:,\s*(?:GET|HEAD|POST|OPTIONS|PUT|DELETE|PATCH))*$/.test(allow)) selected.allow = allow;
  return { headers: selected, contentType, contentLength };
}
export class HttpAnalyzer {
  constructor(private readonly config: UrlAnalysisConfig, private readonly transport: HttpTransport) {}
  async analyze(target: URL, parent: AbortSignal): Promise<HttpResult> {
    const started = Date.now();
    const result = emptyHttp();
    let current = new URL(target.href);
    const visited = new Set<string>();
    let activeSignal = parent;
    const send = async (method: 'HEAD' | 'GET') => {
      if (result.requestCount >= this.config.maxHttpRequests) throw new AnalysisFailure('REQUEST_LIMIT', 'HTTP request budget exhausted');
      activeSignal = AbortSignal.any([parent, AbortSignal.timeout(this.config.requestTimeoutMs)]);
      activeSignal.throwIfAborted();
      result.requestCount++; result.method = method;
      const response = await this.transport(current, method, activeSignal);
      if (!response || !Number.isInteger(response.statusCode) || response.statusCode < 200 || response.statusCode > 599 ||
          !response.headers || typeof response.headers !== 'object') throw new AnalysisFailure('INVALID_HTTP_RESPONSE', 'Malformed HTTP metadata response');
      return response;
    };
    try {
      while (true) {
        parent.throwIfAborted();
        assertNetworkTarget(current, this.config);
        if (visited.has(current.href)) throw new AnalysisFailure('REDIRECT_LOOP', 'Redirect loop detected');
        visited.add(current.href);
        let response = await send('HEAD');
        let details = metadata(response);
        if (result.redirects.length) result.redirects.at(-1)!.followed = true;
        result.statusCode = response.statusCode; result.finalUrl = reportUrl(current.href); Object.assign(result, details);
        if ([405, 501].includes(response.statusCode) || (response.statusCode >= 200 && response.statusCode < 300 && details.contentType === null && details.contentLength === null)) {
          response = await send('GET'); details = metadata(response);
          if (details.contentLength !== null && details.contentLength > this.config.maxResponseBytes) throw new AnalysisFailure('RESPONSE_SIZE_LIMIT', 'GET response declared size exceeds metadata budget');
        }
        result.statusCode = response.statusCode; result.finalUrl = reportUrl(current.href);
        Object.assign(result, details);
        if (!redirectStatuses.has(response.statusCode)) { result.status = 'completed'; break; }
        const location = header(response, 'location');
        if (!location) throw new AnalysisFailure('INVALID_REDIRECT', 'Redirect response lacks a single Location header');
        let next: URL;
        try { next = parseUrl({ url: new URL(location, current).href }, this.config.maxUrlLength).target; }
        catch { throw new AnalysisFailure('INVALID_REDIRECT', 'Redirect target is malformed, credential-bearing or unsupported'); }
        const hop = { url: reportUrl(current.href), statusCode: response.statusCode, target: reportUrl(next.href), crossesRegistrableDomain: crossesDomain(current, next), followed: false };
        result.redirects.push(hop); result.redirectCount = result.redirects.length;
        assertNetworkTarget(next, this.config);
        if (result.redirects.length > this.config.maxRedirects) throw new AnalysisFailure('REDIRECT_LIMIT', 'Redirect budget exhausted');
        if (visited.has(next.href)) throw new AnalysisFailure('REDIRECT_LOOP', 'Redirect loop detected');
        // Actual DNS/address validation occurs inside transport before each connection.
        current = next;
      }
    } catch (error) {
      const detail = structuredError('http', error, activeSignal);
      result.errors.push(detail);
      result.status = detail.code === 'NETWORK_BLOCKED' ? 'blocked' : detail.code === 'TIMEOUT' ? 'timed_out' : detail.code === 'CANCELLED' ? 'cancelled' : 'failed';
    }
    result.responseTimeMs = Date.now() - started;
    return result;
  }
}
