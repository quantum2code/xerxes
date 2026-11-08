import http from 'node:http';
import https from 'node:https';
import type { Socket } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { createGatewayCa } from './gateway-ca.js';
import { createForwarder, type Forwarder, type GatewayPolicy } from './gateway-transport.js';
import { checkScope, scopeUrl } from '../scope/rules.js';
import type { Engine2Config } from '../types.js';
import type { GatewayStatistics } from './job.js';

export async function createPolicyGateway(policy: GatewayPolicy, config: Engine2Config, options: { forward?: Forwarder; phase?: () => { mode: 'idle' | 'crawl' | 'active'; expiresAt: number } } = {}) {
  const ca = await createGatewayCa(policy.expiresAt);
  const forward = options.forward ?? createForwarder(policy, config);
  const stats: GatewayStatistics = { forwarded: 0, denied: 0, failures: 0, exhausted: false };
  const sockets = new Set<Socket>();
  const tlsServers = new Map<string, Promise<https.Server>>();
  let inFlight = 0; let lastRequest = 0;
  const handle = (origin?: URL): http.RequestListener => async (req, res) => {
    // Do not manufacture HTTP error pages: passive ZAP rules could mistake them for target weaknesses.
    const deny = (_status = 403) => { stats.denied++; req.resume(); res.destroy(); };
    let target: URL;
    let phase: { mode: 'idle' | 'crawl' | 'active'; expiresAt: number };
    try {
      target = origin ? new URL(req.url ?? '', origin) : scopeUrl(req.url ?? '');
      if (origin && (target.origin !== origin.origin || scopeUrl(`${origin.protocol}//${req.headers.host}/`).origin !== origin.origin)) return deny();
      phase = options.phase?.() ?? { mode: 'crawl', expiresAt: policy.expiresAt };
      const methods = phase.mode === 'active' && policy.mode === 'active' ? policy.rules.activeMethods : ['GET', 'HEAD'];
      if (phase.mode === 'idle' || Date.now() >= Math.min(policy.expiresAt, phase.expiresAt) || !checkScope(target, policy.rules).allowed || !methods.includes(req.method ?? '') ||
          req.headers.upgrade || req.headers['content-encoding'] || req.headers.expect || inFlight >= 1) return deny();
    } catch { return deny(); }
    if (stats.forwarded >= config.maxRequests) { stats.exhausted = true; return deny(429); }
    inFlight++;
    const cancel = new AbortController();
    const timer = setTimeout(() => cancel.abort(), Math.min(config.requestTimeoutMs, Math.max(1, Math.min(policy.expiresAt, phase.expiresAt) - Date.now())));
    res.once('close', () => { if (!res.writableEnded) cancel.abort(); });
    try {
      const chunks: Buffer[] = []; let size = 0;
      await new Promise<void>((resolve, reject) => {
        const aborted = () => { reject(new Error('Request cancelled')); req.destroy(); };
        cancel.signal.addEventListener('abort', aborted, { once: true });
        req.on('data', (chunk: Buffer) => { size += chunk.length; if (size > config.maxRequestBytes) { reject(new Error('Request size')); req.destroy(); } else chunks.push(chunk); });
        req.once('error', reject); req.once('end', () => { cancel.signal.removeEventListener('abort', aborted); resolve(); });
      });
      const wait = Math.max(0, config.requestIntervalMs - (Date.now() - lastRequest));
      if (wait) await delay(wait, undefined, { signal: cancel.signal });
      cancel.signal.throwIfAborted();
      const currentPhase = options.phase?.() ?? phase;
      if (currentPhase.mode !== phase.mode || Date.now() >= Math.min(policy.expiresAt, currentPhase.expiresAt)) return deny();
      // Never forward caller credentials, cookies, Host overrides, proxy headers or hop-by-hop headers.
      const headers: Record<string, string> = {};
      for (const name of ['accept', 'accept-language', 'content-type']) if (typeof req.headers[name] === 'string') headers[name] = req.headers[name];
      stats.forwarded++; lastRequest = Date.now();
      const response = await forward(target, req.method!, headers, Buffer.concat(chunks), cancel.signal);
      const outgoing: http.OutgoingHttpHeaders = {};
      const hop = new Set(['connection', 'transfer-encoding', 'content-length', 'content-encoding', 'keep-alive', 'upgrade', 'proxy-authenticate', 'proxy-authorization', 'trailer', 'te']);
      for (const [name, value] of Object.entries(response.headers)) if (!hop.has(name.toLowerCase())) outgoing[name] = value;
      // Preserve genuine HTTP/HTTPS URLs and redirect evidence; never follow redirects in this gateway.
      outgoing.connection = 'close';
      res.writeHead(response.status, outgoing); res.end(response.body);
    } catch {
      stats.failures++;
      res.destroy();
    } finally { clearTimeout(timer); inFlight--; }
  };
  const track = (socket: Socket) => {
    if (sockets.size >= 16) { stats.denied++; socket.destroy(); return; }
    sockets.add(socket); socket.once('close', () => sockets.delete(socket)); socket.setTimeout(config.requestTimeoutMs, () => socket.destroy());
  };
  const server = http.createServer({ maxHeaderSize: 16384, requestTimeout: config.requestTimeoutMs, headersTimeout: config.requestTimeoutMs }, handle());
  server.on('connection', track);
  server.on('connect', async (req, socket, head) => {
    try {
      const origin = scopeUrl(`https://${req.url}/`);
      if (origin.pathname !== '/' || origin.search) throw new Error('Invalid CONNECT authority');
      // CONNECT authorizes only the origin; decrypted requests still undergo full path/exclusion checks.
      const originRules = { ...policy.rules, paths: ['/'], excludedPaths: [] };
      if (Date.now() >= policy.expiresAt || !checkScope(origin, originRules).allowed || tlsServers.size >= 32 && !tlsServers.has(origin.origin)) throw new Error();
      let tlsServer = tlsServers.get(origin.origin);
      if (!tlsServer) {
        tlsServer = ca.certificateFor(origin.hostname.replace(/^\[|\]$/g, '')).then((certificate) => {
          const receiver = https.createServer({ ...certificate, maxHeaderSize: 16384, handshakeTimeout: config.requestTimeoutMs, ALPNProtocols: ['http/1.1'] }, handle(origin));
          receiver.on('clientError', (_error, connection) => connection.destroy());
          receiver.on('upgrade', (_request, connection) => { stats.denied++; connection.destroy(); });
          receiver.on('tlsClientError', (_error, connection) => connection.destroy());
          return receiver;
        });
        tlsServers.set(origin.origin, tlsServer);
      }
      const receiver = await tlsServer;
      if (socket.destroyed) return;
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) socket.unshift(head);
      receiver.emit('connection', socket);
    } catch { stats.denied++; socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); }
  });
  server.on('upgrade', (_req, socket) => { stats.denied++; socket.destroy(); });
  server.on('checkContinue', (req, res) => { stats.denied++; req.resume(); res.writeHead(417); res.end(); });
  server.on('clientError', (_error, socket) => socket.destroy());
  return { server, certificate: ca.certificate, stats,
    async close() { for (const socket of sockets) socket.destroy(); server.close(() => {}); for (const receiver of tlsServers.values()) (await receiver).close(() => {}); } };
}
