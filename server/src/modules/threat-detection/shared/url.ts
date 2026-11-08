import { isIP } from 'node:net';
import { parse } from 'tldts';

export const MAX_URL_LENGTH = 8_192;

export function parseHttpUrl(input: string): URL {
  if (typeof input !== 'string' || input.length === 0 || input.length > MAX_URL_LENGTH) {
    throw new TypeError(`URL must be a non-empty string of at most ${MAX_URL_LENGTH} characters`);
  }
  if (input !== input.trim() || /[\s\u0000-\u0020\u007f]/u.test(input)) {
    throw new TypeError('URL must not contain whitespace or control characters');
  }
  // WHATWG URL repairs missing slashes/backslashes; reject ambiguous input before it is normalized.
  if (!/^https?:\/\/[^/?#]+/i.test(input) || input.includes('\\')) {
    throw new TypeError('URL must use explicit http:// or https:// syntax without backslashes');
  }
  const url = new URL(input);
  const hostname = normalizedHostname(url);
  if (!hostname) throw new TypeError('URL must have a hostname');
  if (!isIP(hostname) && (hostname.length > 253 || hostname.split('.').some((label) =>
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)))) {
    throw new TypeError('URL hostname must contain valid DNS labels of at most 63 characters');
  }
  return url;
}

export function normalizedHostname(url: URL): string {
  return url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}

export function domainParts(url: URL) {
  const hostname = normalizedHostname(url);
  const parsed = parse(hostname, { allowPrivateDomains: true });
  return {
    hostname,
    isIp: isIP(hostname) !== 0,
    domain: parsed.domain,
    domainWithoutSuffix: parsed.domainWithoutSuffix,
    publicSuffix: parsed.publicSuffix,
    subdomain: parsed.subdomain || null,
  };
}

/** URL keys preserve query order and path case; fragments are never sent to servers. */
export function canonicalUrl(input: string): string {
  return canonicalizeParsedUrl(parseHttpUrl(input)).href;
}

/** Normalize an already-validated URL in place, avoiding another validation/parsing pass. */
export function canonicalizeParsedUrl(url: URL): URL {
  url.hash = '';
  url.hostname = url.hostname.replace(/\.$/, '');
  return url;
}

/** Canonical keys for reputation lookups; never share URLs containing embedded credentials. */
export function canonicalLookupUrl(input: string): string {
  const url = parseHttpUrl(input);
  if (url.username || url.password) throw new TypeError('URLs with credentials are not allowed');
  return canonicalizeParsedUrl(url).href;
}
