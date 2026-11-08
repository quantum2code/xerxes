import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';

export class PolicyError extends Error {}
export function publicAddress(address: string): boolean {
  try {
    if (address === '168.63.129.16') return false; // Azure platform virtual IP.
    return ipaddr.parse(address).range() === 'unicast';
  } catch { return false; }
}
export type Resolver = (hostname: string) => Promise<{ address: string; family: number }[]>;
export const systemResolver: Resolver = (hostname) => lookup(hostname, { all: true, verbatim: true });
export async function resolvePublic(url: URL, resolver: Resolver = systemResolver): Promise<{ address: string; family: number }> {
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  const addresses = isIP(hostname) ? [{ address: hostname, family: isIP(hostname) }] : await resolver(hostname);
  if (!addresses.length || addresses.some(({ address }) => !publicAddress(address))) throw new PolicyError('Target resolves to a prohibited network');
  return addresses[0]!;
}
export interface AddressInfo {
  address: string;
  version: 4 | 6;
  category: string;
  publiclyRoutable: boolean;
  mappedIpv4: string | null;
}
export function classifyAddress(address: string): AddressInfo {
  const parsed = ipaddr.parse(address);
  return {
    address: parsed.toString(), version: parsed.kind() === 'ipv4' ? 4 : 6,
    category: address === '168.63.129.16' ? 'platform-service' : parsed.range(),
    publiclyRoutable: publicAddress(address),
    mappedIpv4: parsed.kind() === 'ipv6' && (parsed as ipaddr.IPv6).isIPv4MappedAddress() ? (parsed as ipaddr.IPv6).toIPv4Address().toString() : null,
  };
}
