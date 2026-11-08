import { Agent, buildConnector, request } from 'undici';
import { Resolver } from 'node:dns/promises';
import { isIP } from 'node:net';
import type { TLSSocket } from 'node:tls';
import ipaddr from 'ipaddr.js';
import { publicAddress } from '../../../shared/network/policy.js';
import { Engine2Failure } from '../errors.js';
import { checkScope } from '../scope/rules.js';
import type { Engine2Config, ScopeRules } from '../types.js';

export interface GatewayPolicy { rules: ScopeRules; mode: 'passive' | 'active'; expiresAt: number; labAddresses: string[]; }
export interface ForwardResponse { status: number; headers: Record<string, string | string[] | undefined>; body: Buffer; }
export type Forwarder = (url: URL, method: string, headers: Record<string, string>, body: Buffer, signal: AbortSignal) => Promise<ForwardResponse>;
export type AddressLookup = (hostname: string, signal: AbortSignal) => Promise<{ address: string; family: number }[]>;
export type GatewayRequest = (url: URL, options: Parameters<typeof request>[1]) => ReturnType<typeof request>;

export function addressAllowed(address: string, policy: GatewayPolicy): boolean {
  if (policy.rules.profile === 'public') return publicAddress(address);
  try { return policy.labAddresses.some((allowed) => ipaddr.process(allowed).toString() === ipaddr.process(address).toString()); }
  catch { return false; }
}
const nativeLookup: AddressLookup = async (hostname, signal) => {
  const literal = isIP(hostname);
  if (literal) return [{ address: hostname, family: literal }];
  const resolver = new Resolver({ timeout: 3000, tries: 1 });
  const abort = () => resolver.cancel(); signal.addEventListener('abort', abort, { once: true });
  try {
    signal.throwIfAborted();
    const outcomes = await Promise.allSettled([resolver.resolve4(hostname), resolver.resolve6(hostname)]);
    const addresses: { address: string; family: number }[] = [];
    for (let index = 0; index < outcomes.length; index++) {
      const outcome = outcomes[index]!;
      if (outcome.status === 'fulfilled') addresses.push(...outcome.value.map((address) => ({ address, family: index === 0 ? 4 : 6 })));
      else if (outcome.reason?.code !== 'ENODATA') throw new Engine2Failure('DNS_FAILED', 'Complete address validation unavailable');
    }
    signal.throwIfAborted(); return addresses;
  } finally { signal.removeEventListener('abort', abort); resolver.cancel(); }
};
export function pinnedGatewayConnector(url: URL, address: { address: string; family: number }, policy: GatewayPolicy, config: Engine2Config,
  builder: typeof buildConnector = buildConnector): buildConnector.connector {
  if (!addressAllowed(address.address, policy) || isIP(address.address) !== address.family) throw new Engine2Failure('NETWORK_BLOCKED', 'Prohibited connection address');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const connector = builder({ family: address.family, autoSelectFamily: false, rejectUnauthorized: true, timeout: config.requestTimeoutMs,
    allowH2: false, maxCachedSessions: 0, lookup: (_hostname, _options, callback) => callback(null, address.address, address.family) });
  return (options, callback) => {
    if (options.hostname.replace(/^\[|\]$/g, '') !== host || options.protocol !== url.protocol || Number(options.port) !== Number(url.port || (url.protocol === 'https:' ? 443 : 80)) || options.socketPath || options.httpSocket) {
      callback(new Engine2Failure('NETWORK_BLOCKED', 'Connection origin mismatch'), null); return;
    }
    connector({ ...options, hostname: host, servername: url.protocol === 'https:' && !isIP(host) ? host : '' }, (error, socket) => {
      if (error) { callback(error, null); return; }
      let valid = false;
      try { valid = !!socket.remoteAddress && addressAllowed(socket.remoteAddress, policy) && ipaddr.process(socket.remoteAddress).toString() === ipaddr.process(address.address).toString() && (url.protocol !== 'https:' || (socket as TLSSocket).authorized); } catch { /* Invalid peers are never passed to Undici. */ }
      if (!valid) { socket.destroy(); callback(new Engine2Failure('NETWORK_BLOCKED', 'Connection-time address/TLS verification failed'), null); return; }
      callback(null, socket);
    });
  };
}
export function createForwarder(policy: GatewayPolicy, config: Engine2Config, lookup: AddressLookup = nativeLookup, send: GatewayRequest = request): Forwarder {
  return async (url, method, headers, body, parent) => {
    if (Date.now() >= policy.expiresAt || !checkScope(url, policy.rules).allowed) throw new Engine2Failure('SCOPE_BLOCKED', 'Request outside authorized scope');
    const signal = AbortSignal.any([parent, AbortSignal.timeout(config.requestTimeoutMs)]);
    const addresses = policy.rules.profile === 'isolated-lab' ? policy.labAddresses.map((address) => ({ address, family: isIP(address) })) : await lookup(url.hostname.replace(/^\[|\]$/g, ''), signal);
    signal.throwIfAborted();
    if (!addresses.length || addresses.some((a) => !addressAllowed(a.address, policy))) throw new Engine2Failure('NETWORK_BLOCKED', 'DNS contained prohibited or unvalidated addresses');
    const dispatcher = new Agent({ connect: pinnedGatewayConnector(url, addresses[0]!, policy, config), connections: 1, pipelining: 0,
      maxResponseSize: config.maxResponseBytes, maxHeaderSize: 16384, allowH2: false });
    try {
      const response = await send(url, { dispatcher, method: method as 'GET' | 'HEAD' | 'POST' | 'OPTIONS', signal,
        headersTimeout: config.requestTimeoutMs, bodyTimeout: config.requestTimeoutMs,
        headers: { ...headers, 'accept-encoding': 'identity', 'user-agent': 'Xerxes-Engine2/1.0' }, body: body.length ? body : undefined });
      response.body.on('error', () => {});
      const encoding = response.headers['content-encoding'];
      if (encoding && encoding !== 'identity') { response.body.destroy(); throw new Engine2Failure('RESPONSE_ENCODING', 'Compressed responses are not accepted by the bounded policy gateway'); }
      const chunks: Buffer[] = []; let size = 0;
      for await (const chunk of response.body) {
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); size += bytes.length;
        if (size > config.maxResponseBytes) { response.body.destroy(); throw new Engine2Failure('RESPONSE_LIMIT', 'Response size limit exceeded'); }
        chunks.push(bytes);
      }
      return { status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks) };
    } finally { await dispatcher.destroy(); }
  };
}
