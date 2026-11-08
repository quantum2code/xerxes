import type { UrlFeatures } from '../types.js';
import type { ParsedUrl } from './parser.js';

/** Shannon entropy over Unicode code points, in bits per character, not a maliciousness score. */
export function entropy(text: string): number {
  const chars = Array.from(text);
  const counts = new Map<string, number>();
  for (const char of chars) counts.set(char, (counts.get(char) ?? 0) + 1);
  return chars.length ? Math.max(0, -[...counts.values()].reduce((sum, n) => { const p = n / chars.length; return sum + p * Math.log2(p); }, 0)) : 0;
}
export function extractFeatures({ raw, target, data, rawHostname }: ParsedUrl): UrlFeatures {
  const count = (pattern: RegExp) => (raw.match(pattern) ?? []).length;
  let decoded = raw;
  try { decoded = decodeURIComponent(raw); } catch { /* Invalid percent escapes remain lexical features. */ }
  const words = new Set(decoded.toLowerCase().split(/[^a-z]+/));
  return {
    urlLength: raw.length, hostnameLength: data.hostname.length, pathLength: target.pathname.length,
    subdomainCount: data.subdomain ? data.subdomain.split('.').length : 0, queryParameterCount: data.queryParameterCount,
    dotCount: count(/\./g), hyphenCount: count(/-/g), digitCount: count(/[0-9]/g), specialCharacterCount: count(/[^a-z0-9]/gi),
    hasIpAddress: data.isIpAddress, hasPunycode: data.domainLabels.some((label) => label.startsWith('xn--')), hasPercentEncoding: /%[0-9a-f]{2}/i.test(raw),
    unusualPort: data.port !== (data.scheme === 'https' ? 443 : 80), nonCanonicalIpv4: data.ipVersion === 4 && rawHostname !== data.hostname,
    repeatedSlashes: /\/{2,}/.test(target.pathname), repeatedEncoding: /%25[0-9a-f]{2}/i.test(raw), embeddedUrlSyntax: /https?:\/\//i.test(raw.slice(raw.indexOf('://') + 3)),
    entropyBitsPerCharacter: entropy(raw),
    terms: { login: words.has('login'), verify: words.has('verify'), account: words.has('account'), secure: words.has('secure'), update: words.has('update') },
  };
}
