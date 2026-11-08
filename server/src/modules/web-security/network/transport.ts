import http from 'node:http';
import https from 'node:https';
import { type TLSSocket } from 'node:tls';
import ipaddr from 'ipaddr.js';
import type { Page, ScannerConfig } from '../types.js';
import { parseTarget, PolicyError, publicAddress, resolvePublic, type Resolver } from './policy.js';

export interface RequestInit { method?: string; body?: Buffer; contentType?: string; }
export type Transport = (url: URL, signal: AbortSignal, init?: RequestInit) => Promise<Page>;
export type RequestFactory = (url: URL, options: http.RequestOptions) => http.ClientRequest;
/** No connection pooling, environment proxies, automatic redirects, cookies, or credential forwarding. */
export function createTransport(config: ScannerConfig, resolver?: Resolver, factory?: RequestFactory): Transport {
  return async (url, parentSignal, init = {}) => {
    parseTarget(url.href);
    const signal = AbortSignal.any([parentSignal, AbortSignal.timeout(config.requestTimeoutMs)]);
    // DNS lookup is itself deadline-bounded. A late DNS completion never starts a connection.
    const address = await new Promise<Awaited<ReturnType<typeof resolvePublic>>>((resolve, reject) => {
      const abort = () => reject(new Error('Request deadline exceeded'));
      signal.addEventListener('abort', abort, { once: true });
      if (signal.aborted) abort();
      resolvePublic(url, resolver).then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
    });
    signal.throwIfAborted();
    return new Promise<Page>((resolve, reject) => {
      const secure = url.protocol === 'https:';
      const request = (factory ?? (secure ? https : http).request)(url, {
        agent: false, signal, maxHeaderSize: 16_384, method: init.method ?? 'GET',
        // An explicit family also prevents Node's autoSelectFamily/all-address lookup path.
        family: address.family,
        // Connect directly to the validated address while retaining original Host/SNI and certificate verification.
        lookup: (_hostname, _options, callback) => callback(null, address.address, address.family),
        headers: { 'user-agent': 'Xerxes-WebSecurity/1.0', accept: 'text/html,application/javascript,text/plain;q=0.8', 'accept-encoding': 'identity',
          ...(init.body ? { 'content-length': String(init.body.length) } : {}), ...(init.contentType ? { 'content-type': init.contentType } : {}) },
      });
      request.on('socket', (socket) => {
        socket.once('connect', () => {
          const peer = socket.remoteAddress;
          if (!peer || !publicAddress(peer) || ipaddr.process(peer).toString() !== ipaddr.process(address.address).toString()) {
            request.destroy(new PolicyError('Connection address verification failed'));
          }
        });
        if (secure) (socket as TLSSocket).once('secureConnect', () => {
          if (!(socket as TLSSocket).authorized) request.destroy(new Error('TLS verification failed'));
        });
      });
      request.once('error', reject);
      request.once('response', (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        if (response.headers['content-encoding'] && response.headers['content-encoding'] !== 'identity') {
          response.destroy(); request.destroy(new Error('Unsupported response encoding')); return;
        }
        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > config.maxResponseBytes) { response.destroy(); request.destroy(new Error('Response size limit exceeded')); }
          else chunks.push(chunk);
        });
        response.once('error', reject);
        response.once('aborted', () => reject(new Error('Response interrupted')));
        response.once('end', () => resolve({ url: url.href, status: response.statusCode ?? 0, headers: response.headers as Page['headers'], body: Buffer.concat(chunks).toString('utf8') }));
      });
      request.end(init.body);
    });
  };
}
