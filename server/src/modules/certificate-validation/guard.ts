// Network safety for the TLS probe. Self-contained on purpose: Engine 3 does not import from any other module.
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';

export class PolicyError extends Error {}

export type Resolver = (hostname: string) => Promise<{ address: string; family: number }[]>;
export const systemResolver: Resolver = (hostname) => lookup(hostname, { all: true, verbatim: true });

const LOCAL_NAMES = /(?:^|\.)(?:localhost|local|internal|home|lan|test|invalid|onion)\.?$/i;

/** Strict target check for a TLS probe: https only, no credentials, port 443, no local-looking names. */
export function parseTlsTarget(raw: unknown): URL {
  if (typeof raw !== 'string' || raw.length > 4096 || /[\u0000-\u0020\u007f\\]/.test(raw)) throw new PolicyError('Invalid target URL');
  let url: URL;
  try { url = new URL(raw); } catch { throw new PolicyError('Invalid target URL'); }
  if (url.protocol !== 'https:' || url.username || url.password || !url.hostname || (url.port && url.port !== '443')) {
    throw new PolicyError('Only credential-free HTTPS URLs on port 443 are allowed');
  }
  if (LOCAL_NAMES.test(url.hostname) || url.hostname.endsWith('.')) throw new PolicyError('Prohibited hostname');
  return url;
}

/** Only globally routable unicast addresses. Private, loopback, link-local, multicast, reserved, mapped and NAT64 are refused. */
export function publicAddress(address: string): boolean {
  try {
    if (address === '168.63.129.16') return false; // Azure platform address, never an Internet target
    return ipaddr.parse(address).range() === 'unicast';
  } catch { return false; }
}

/** Every DNS answer must be public. Returns the first one, which the caller connects to directly. */
export async function resolvePublic(url: URL, resolver: Resolver = systemResolver): Promise<{ address: string; family: number }> {
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  const addresses = isIP(hostname) ? [{ address: hostname, family: isIP(hostname) }] : await resolver(hostname);
  if (!addresses.length || addresses.some(({ address }) => !publicAddress(address))) throw new PolicyError('Target resolves to a prohibited network');
  return addresses[0]!;
}