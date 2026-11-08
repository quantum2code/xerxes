import { isIP } from 'node:net';
import { domainToUnicode } from 'node:url';
import { domainParts, parseHttpUrl } from '../shared/url.js';
import { extractParsedUrlFeatures, URL_KEYWORDS } from '../shared/url-features.js';
import type { BasicUrlAnalysis, UrlSignal } from './types.js';

function keywordMatches(value: string): string[] {
  // Decode once, not recursively. Malformed escapes must not make analysis fail.
  let decoded = value;
  try { decoded = decodeURIComponent(value); } catch { /* Keep the serialized component. */ }
  return [...new Set((decoded.match(URL_KEYWORDS) ?? []).map((word) => word.toLowerCase()))];
}

function unusualIpv4Notation(input: string, hostname: string): boolean {
  if (isIP(hostname) !== 4) return false;
  const authority = /^https?:\/\/([^/?#]+)/i.exec(input)![1]!;
  const hostPort = authority.slice(authority.lastIndexOf('@') + 1);
  const originalHost = hostPort.split(':', 1)[0]!.replace(/\.$/, '');
  return isIP(originalHost) !== 4;
}

/** Structural indicators only: neither their presence nor their absence establishes phishing. */
export function analyzeBasicUrl(input: string): BasicUrlAnalysis {
  const url = parseHttpUrl(input);
  const parts = domainParts(url);
  const features = extractParsedUrlFeatures(url, parts);
  const signals: UrlSignal[] = [];
  const add = (
    condition: boolean, code: UrlSignal['code'],
    location: UrlSignal['location'], description: string, evidence: UrlSignal['evidence'],
  ) => {
    if (condition) signals.push({ code, location, description, evidence });
  };
  add(!features.usesHttps, 'http', 'scheme', 'URL does not use HTTPS', { value: url.protocol });
  add(Boolean(features.hasIpHost), 'ip_host', 'hostname', 'Host is an IP address rather than a domain name', { value: parts.hostname });
  add(Boolean(features.hasCredentials), 'credentials', 'userinfo', 'URL contains embedded user information', { value: 'present' });
  add(Boolean(features.hasPunycode), 'punycode', 'hostname', 'Internationalized hostname; inspect its Unicode spelling', { value: parts.hostname });
  add(Boolean(features.hasNonDefaultPort), 'non_default_port', 'port', 'URL uses a non-default port', { value: url.port });
  add(features.urlLength > 200, 'long_url', 'url', 'URL exceeds 200 characters', { value: features.urlLength, threshold: 200 });
  add(features.subdomainCount >= 3, 'many_subdomains', 'hostname', 'Hostname has at least three subdomain labels', { value: features.subdomainCount, threshold: 3 });
  add(features.hyphenCount >= 3, 'many_hyphens', 'hostname', 'Hostname contains at least three hyphens', { value: features.hyphenCount, threshold: 3 });
  add(features.percentEncodedCount >= 5, 'encoded_characters', 'url', 'URL contains at least five percent-encoded characters', { value: features.percentEncodedCount, threshold: 5 });

  const localHostname = !parts.isIp && (!parts.hostname.includes('.')
    || /(?:^|\.)(?:localhost|local|internal|home\.arpa)$/.test(parts.hostname));
  add(localHostname, 'local_hostname', 'hostname', 'Hostname is single-label or uses a local/internal naming suffix; DNS reachability is not checked', { value: parts.hostname });
  add(unusualIpv4Notation(input, parts.hostname), 'unusual_ip_notation', 'hostname', 'Original hostname uses a non-standard IPv4 representation', { value: parts.hostname });

  const components = [
    ['hostname', parts.hostname], ['path', url.pathname], ['query', url.search], ['fragment', url.hash],
  ] as const;
  for (const [location, value] of components) {
    const matches = keywordMatches(value);
    add(matches.length > 0, 'sensitive_keywords', location,
      'URL component contains authentication, account, or recovery terms; legitimate URLs commonly do too',
      { value: matches.length, matches });
  }

  const display = new URL(url.href);
  display.username = '';
  display.password = '';
  return {
    normalizedUrl: url.href,
    displayUrl: display.href,
    hostname: parts.hostname,
    unicodeHostname: parts.isIp ? parts.hostname : domainToUnicode(parts.hostname),
    registrableDomain: parts.domain,
    publicSuffix: parts.publicSuffix,
    subdomain: parts.subdomain,
    features,
    signals,
  };
}
