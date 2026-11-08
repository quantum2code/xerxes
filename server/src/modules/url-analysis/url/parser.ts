import { domainToASCII, domainToUnicode } from 'node:url';
import { isIP } from 'node:net';
import { parse } from 'tldts';
import { z } from 'zod';
import type { UrlData } from '../types.js';
import { AnalysisFailure } from '../errors.js';
import { reportUrl } from './normalize.js';

export interface ParsedUrl { target: URL; data: UrlData; raw: string; rawHostname: string; }
export function parseUrl(input: unknown, maxLength = 4096): ParsedUrl {
  const parsed = z.object({ url: z.string().min(1).max(maxLength) }).safeParse(input);
  if (!parsed.success) throw new AnalysisFailure('INVALID_INPUT', 'Expected an object with a bounded URL string');
  const raw = parsed.data.url;
  if (!/^https?:\/\//i.test(raw) || /[\u0000-\u0020\u007f\\]/.test(raw)) throw new AnalysisFailure('INVALID_URL', 'An absolute, unambiguous HTTP(S) URL is required');
  let url: URL;
  try { url = new URL(raw); } catch { throw new AnalysisFailure('INVALID_URL', 'URL parsing failed'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || !url.hostname) throw new AnalysisFailure('INVALID_URL', 'Unsupported scheme or embedded credentials');
  const hostname = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  const ipVersion = isIP(hostname) as 0 | 4 | 6;
  const observedSuffix = ipVersion ? null : parse(hostname, { allowPrivateDomains: true });
  // tldts can heuristically split unknown suffixes; do not label those as PSL registrable domains.
  const suffix = observedSuffix && (observedSuffix.isIcann || observedSuffix.isPrivate) ? observedSuffix : null;
  // Lexical authority is used only for features (explicit default ports/noncanonical IPv4), never for connecting.
  const authority = raw.slice(raw.indexOf('://') + 3).split(/[/?#]/, 1)[0]!;
  if (authority.includes('@')) throw new AnalysisFailure('INVALID_URL', 'Embedded user information is not allowed');
  const rawHostname = authority.startsWith('[') ? authority.slice(1, authority.indexOf(']')) : authority.split(':', 1)[0]!;
  const explicitPort = authority.startsWith('[') ? /\]:\d+$/.test(authority) : /:\d+$/.test(authority);
  const data: UrlData = {
    original: reportUrl(raw, true), normalized: reportUrl(url.href), scheme: url.protocol === 'https:' ? 'https' : 'http',
    hostname, asciiHostname: ipVersion ? hostname : domainToASCII(hostname), unicodeHostname: ipVersion ? hostname : domainToUnicode(hostname),
    port: Number(url.port || (url.protocol === 'https:' ? 443 : 80)), explicitPort,
    path: new URL(reportUrl(url.href)).pathname,
    queryParameterNames: [...url.searchParams.keys()], queryParameterCount: url.searchParams.size,
    hasFragment: raw.includes('#'), domain: suffix?.domain ?? null, publicSuffix: suffix?.publicSuffix ?? null, subdomain: suffix?.subdomain || null,
    domainLabels: ipVersion ? [] : hostname.split('.'), isIpAddress: ipVersion !== 0, ipVersion: ipVersion || null,
  };
  url.hash = '';
  return { target: url, data, raw, rawHostname };
}
