import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';

export interface TlsTarget {
  /** Name the user asked for. Used for SNI only. */
  hostname: string;
  /** Already validated public IP. We connect to this, never to the name (no second DNS lookup). */
  address: string;
  port: number;
}

export interface PeerCertificate {
  cert: X509Certificate;
  /** Everything the server presented, leaf first (plus any root OpenSSL found). Absent in simple test doubles. */
  chain?: X509Certificate[];
  authorized: boolean;
  /** Verification error code from the handshake, e.g. CERT_HAS_EXPIRED. */
  authorizationError?: string;
}

export type Connector = (target: TlsTarget, timeoutMs: number) => Promise<PeerCertificate>;

function errorCode(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (value instanceof Error) return (value as NodeJS.ErrnoException).code ?? value.message;
  return undefined;
}

/** Walks issuerCertificate links (leaf first). Stops at a self-referencing root, a repeat, or 10 certificates. */
export function chainFromPeer(peer: tls.DetailedPeerCertificate): X509Certificate[] {
  const chain: X509Certificate[] = [];
  const seen = new Set<string>();
  let current: tls.DetailedPeerCertificate | undefined = peer;
  while (current?.raw && chain.length < 10 && !seen.has(current.fingerprint256)) {
    seen.add(current.fingerprint256);
    chain.push(new X509Certificate(current.raw));
    current = current.issuerCertificate === current ? undefined : current.issuerCertificate;
  }
  return chain;
}

/** Handshake with verification turned off so a bad certificate can still be read and judged by us. */
export const connectTls: Connector = (target, timeoutMs) =>
  new Promise((resolve, reject) => {
    let settled = false;
    const socket = tls.connect({
      host: target.address,
      port: target.port,
      servername: isIP(target.hostname) ? undefined : target.hostname,
      rejectUnauthorized: false,
    });
    const finish = (action: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      action();
    };
    const timer = setTimeout(() => finish(() => reject(Object.assign(new Error('TLS handshake timed out'), { code: 'ETIMEDOUT' }))), timeoutMs);
    socket.once('error', (error) => finish(() => reject(error)));
    socket.once('secureConnect', () => {
      try {
        const chain = chainFromPeer(socket.getPeerCertificate(true));
        if (!chain.length) throw Object.assign(new Error('Server presented no certificate'), { code: 'NO_CERTIFICATE' });
        const result: PeerCertificate = {
          cert: chain[0]!,
          chain,
          authorized: socket.authorized,
          authorizationError: errorCode(socket.authorizationError),
        };
        finish(() => resolve(result));
      } catch (error) {
        finish(() => reject(error));
      }
    });
  });