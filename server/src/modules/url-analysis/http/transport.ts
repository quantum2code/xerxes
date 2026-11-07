import { Agent, request } from 'undici';
import { Semaphore } from '../../../shared/network/limits.js';
import { resolvePublic } from '../../../shared/network/policy.js';
import type { DnsAnalyzer } from '../dns/resolver.js';
import type { UrlAnalysisConfig } from '../types.js';
import { assertNetworkTarget } from '../security/ip-validation.js';
import { createPinnedConnector } from '../security/safe-connection.js';
import { AnalysisFailure } from '../errors.js';

export interface HttpSnapshot { statusCode: number; headers: Record<string, string | string[] | undefined>; }
export type HttpTransport = (url: URL, method: 'HEAD' | 'GET', signal: AbortSignal) => Promise<HttpSnapshot>;
export type MetadataRequest = (url: URL, options: Parameters<typeof request>[1]) => ReturnType<typeof request>;
export function createHttpTransport(config: UrlAnalysisConfig, dns: DnsAnalyzer, send: MetadataRequest = request): HttpTransport {
  const concurrency = new Semaphore(config.httpConcurrency);
  return (url, method, parent) => {
    const signal = AbortSignal.any([parent, AbortSignal.timeout(config.requestTimeoutMs)]);
    return concurrency.run(signal, async () => {
      assertNetworkTarget(url, config);
      const approved = await resolvePublic(url, (host) => dns.connectionAddresses(host, signal));
      signal.throwIfAborted();
      const dispatcher = new Agent({ connect: createPinnedConnector(url, approved, config),
        connections: 1, pipelining: 0, allowH2: false, maxResponseSize: config.maxResponseBytes, maxHeaderSize: config.maxHeaderBytes });
      try {
        // Undici's low-level request API does not follow redirects; no redirect interceptor is installed.
        const response = await send(url, { dispatcher, method, signal,
          headersTimeout: config.requestTimeoutMs, bodyTimeout: config.requestTimeoutMs,
          headers: { 'user-agent': config.userAgent, accept: '*/*', 'accept-encoding': 'identity' } });
        // Metadata only: never read, decompress, store, execute, or drain the page body.
        response.body.on('error', () => {});
        response.body.destroy();
        const length = response.headers['content-length'];
        if (method === 'GET' && typeof length === 'string' && /^\d+$/.test(length) && Number(length) > config.maxResponseBytes) {
          throw new AnalysisFailure('RESPONSE_SIZE_LIMIT', 'GET response declared size exceeds metadata budget');
        }
        return { statusCode: response.statusCode, headers: response.headers };
      } finally { await dispatcher.destroy(); }
    });
  };
}
