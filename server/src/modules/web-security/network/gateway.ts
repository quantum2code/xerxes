import http from 'node:http';
import type { ScannerConfig } from '../types.js';
import { parseTarget, PolicyError } from './policy.js';
import { createTransport, type Transport } from './transport.js';

export interface GatewayPolicy { origin: string; proxyOrigin: string; maxRequests: number; expiresAt: number; }
export interface GatewayState { forwarded: number; denied: number; failures: number; exhausted: boolean; }
/** Explicit HTTP proxy only: CONNECT, upgrades, arbitrary headers and automatic redirects are forbidden. */
export function createGateway(policy: GatewayPolicy, config: ScannerConfig, transport: Transport = createTransport(config)) {
  const target = parseTarget(policy.origin);
  const proxy = parseTarget(policy.proxyOrigin);
  if (target.origin !== policy.origin || proxy.origin !== policy.proxyOrigin || proxy.protocol !== 'http:' ||
      proxy.hostname !== target.hostname || !Number.isSafeInteger(policy.maxRequests) || policy.maxRequests < 1 ||
      policy.maxRequests > config.maxRequests || !Number.isFinite(policy.expiresAt) || policy.expiresAt > Date.now() + config.zap.timeoutMs) throw new PolicyError('Invalid gateway policy');
  const state: GatewayState = { forwarded: 0, denied: 0, failures: 0, exhausted: false };
  let busy = false;
  let lastRequest = 0;
  const server = http.createServer({ maxHeaderSize: 16_384, requestTimeout: config.requestTimeoutMs, headersTimeout: config.requestTimeoutMs }, async (req, res) => {
    const deny = (code = 403) => { state.denied++; res.writeHead(code, { connection: 'close' }); res.end('Xerxes policy denied request'); req.resume(); };
    let input: URL;
    try {
      input = parseTarget(req.url);
      if (input.origin !== policy.proxyOrigin || !['GET', 'HEAD', 'POST', 'OPTIONS'].includes(req.method ?? '') ||
          req.headers['content-encoding'] || req.headers.expect || busy || Date.now() >= policy.expiresAt) return deny();
    } catch { return deny(); }
    if (state.forwarded >= policy.maxRequests) { state.exhausted = true; return deny(429); }
    busy = true;
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), Math.min(config.requestTimeoutMs, Math.max(1, policy.expiresAt - Date.now())));
    req.once('aborted', () => abort.abort());
    try {
      const chunks: Buffer[] = [];
      let size = 0;
      await new Promise<void>((resolve, reject) => {
        const onAbort = () => { req.destroy(); reject(new Error('Gateway deadline')); };
        abort.signal.addEventListener('abort', onAbort, { once: true });
        req.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 65_536) { req.destroy(); reject(new Error('Request body limit')); } else chunks.push(chunk); });
        req.once('error', reject);
        req.once('end', () => { abort.signal.removeEventListener('abort', onAbort); resolve(); });
      });
      const wait = Math.max(0, config.requestIntervalMs - (Date.now() - lastRequest));
      if (wait) await import('node:timers/promises').then(({ setTimeout }) => setTimeout(wait, undefined, { signal: abort.signal }));
      abort.signal.throwIfAborted();
      // Construct from the authorized origin; no Host, Authorization or Cookie supplied by ZAP is forwarded.
      const actual = new URL(input.pathname + input.search, target);
      if (actual.origin !== target.origin) throw new PolicyError('Out of scope');
      state.forwarded++; lastRequest = Date.now();
      const page = await transport(actual, abort.signal, { method: req.method, body: chunks.length ? Buffer.concat(chunks) : undefined, contentType: typeof req.headers['content-type'] === 'string' ? req.headers['content-type'] : undefined });
      const headers: http.OutgoingHttpHeaders = {};
      const hop = new Set(['connection', 'transfer-encoding', 'content-length', 'keep-alive', 'upgrade', 'proxy-authenticate', 'proxy-authorization', 'trailer', 'te', 'content-encoding']);
      for (const [name, value] of Object.entries(page.headers)) if (!hop.has(name.toLowerCase())) headers[name] = value;
      // Redirects are returned, never followed here. ZAP can follow only through this same policy gateway.
      const location = headers.location;
      if (typeof location === 'string') {
        const next = new URL(location, actual);
        // Preserve off-origin Location as evidence (needed for open-redirect detection),
        // but never fetch it. Any follow-up by ZAP must pass this gateway's origin check.
        if (next.origin === target.origin) headers.location = new URL(next.pathname + next.search, proxy).href;
      }
      headers.connection = 'close';
      res.writeHead(page.status, headers); res.end(page.body);
    } catch {
      state.failures++;
      if (!res.headersSent && !res.destroyed) { res.writeHead(502, { connection: 'close' }); res.end('Xerxes upstream request failed'); }
    } finally { clearTimeout(timer); busy = false; }
  });
  server.on('connect', (_req, socket) => { state.denied++; socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); });
  server.on('upgrade', (_req, socket) => { state.denied++; socket.destroy(); });
  server.on('checkContinue', (req, res) => { state.denied++; res.writeHead(417); res.end(); req.resume(); });
  server.on('clientError', (_err, socket) => socket.destroy());
  return { server, state };
}
