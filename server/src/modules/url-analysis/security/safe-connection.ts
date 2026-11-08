import { buildConnector } from 'undici';
import { isIP } from 'node:net';
import type { TLSSocket } from 'node:tls';
import ipaddr from 'ipaddr.js';
import { PolicyError, publicAddress } from '../../../shared/network/policy.js';
import type { UrlAnalysisConfig } from '../types.js';
import { AnalysisFailure } from '../errors.js';

/** Return a socket to Undici only after address and TLS checks; no HTTP bytes precede verification. */
export function createPinnedConnector(url: URL, approved: { address: string; family: number }, config: UrlAnalysisConfig,
  builder: typeof buildConnector = buildConnector): buildConnector.connector {
  if (!publicAddress(approved.address) || isIP(approved.address) !== approved.family) throw new PolicyError('Invalid approved connection address');
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  const connector = builder({
    timeout: config.requestTimeoutMs, rejectUnauthorized: true, family: approved.family, autoSelectFamily: false,
    maxCachedSessions: 0, allowH2: false,
    lookup: (_hostname, _options, callback) => callback(null, approved.address, approved.family),
  });
  return (options, callback) => {
    if (options.hostname.replace(/^\[|\]$/g, '').toLowerCase() !== hostname.toLowerCase() || options.protocol !== url.protocol ||
        Number(options.port || (url.protocol === 'https:' ? 443 : 80)) !== Number(url.port || (url.protocol === 'https:' ? 443 : 80)) || options.httpSocket || options.socketPath) {
      callback(new PolicyError('Connector origin mismatch'), null); return;
    }
    connector({ ...options, hostname, servername: url.protocol === 'https:' && !isIP(hostname) ? hostname : '' }, (error, socket) => {
      if (error) { callback(error, null); return; }
      try {
        const peer = socket.remoteAddress ? ipaddr.process(socket.remoteAddress).toString() : '';
        if (!peer || !publicAddress(peer) || peer !== ipaddr.process(approved.address).toString()) throw new PolicyError('Connection address verification failed');
        if (url.protocol === 'https:' && !(socket as TLSSocket).authorized) throw new AnalysisFailure('TLS_VERIFICATION_FAILED', 'TLS connection verification failed');
        callback(null, socket);
      } catch (failure) { socket.destroy(); callback(failure instanceof Error ? failure : new PolicyError('Unsafe socket'), null); }
    });
  };
}
