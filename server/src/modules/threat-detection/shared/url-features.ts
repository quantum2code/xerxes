import { domainParts, parseHttpUrl } from './url.js';

/** Ordered model contract. Changing a feature or its meaning requires a new model format. */
export const URL_FEATURE_NAMES = [
  'urlLength', 'hostnameLength', 'pathLength', 'queryLength', 'digitRatio',
  'hostnameDigitRatio', 'hostnameEntropy', 'dotCount', 'hyphenCount',
  'subdomainCount', 'queryParameterCount', 'percentEncodedCount', 'hasIpHost',
  'hasCredentials', 'usesHttps', 'hasPunycode', 'hasNonDefaultPort', 'suspiciousWordCount',
] as const;

export type UrlFeatureName = typeof URL_FEATURE_NAMES[number];
export type UrlFeatures = Record<UrlFeatureName, number>;
export const URL_KEYWORDS = /(?:login|signin|verify|verification|password|secure|account|update|wallet|recover)/gi;

function digitRatio(value: string): number {
  return value.length === 0 ? 0 : (value.match(/[0-9]/g)?.length ?? 0) / value.length;
}

function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1);
  let result = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    result -= probability * Math.log2(probability);
  }
  return result;
}

/** Offline, deterministic lexical features; no DNS, page fetch, or reputation lookup. */
export function extractUrlFeatures(input: string): UrlFeatures {
  return extractParsedUrlFeatures(parseHttpUrl(input));
}

/** Internal reuse for analyzers that have already validated and parsed the URL. */
export function extractParsedUrlFeatures(url: URL, parts = domainParts(url)): UrlFeatures {
  const value = url.href;
  return {
    urlLength: value.length,
    hostnameLength: parts.hostname.length,
    pathLength: url.pathname.length,
    queryLength: url.search.length,
    digitRatio: digitRatio(value),
    hostnameDigitRatio: digitRatio(parts.hostname),
    hostnameEntropy: entropy(parts.hostname),
    dotCount: (parts.hostname.match(/\./g) ?? []).length,
    hyphenCount: (parts.hostname.match(/-/g) ?? []).length,
    subdomainCount: parts.subdomain?.split('.').length ?? 0,
    queryParameterCount: [...url.searchParams].length,
    percentEncodedCount: (value.match(/%[\da-f]{2}/gi) ?? []).length,
    hasIpHost: Number(parts.isIp),
    hasCredentials: Number(Boolean(url.username || url.password)),
    usesHttps: Number(url.protocol === 'https:'),
    hasPunycode: Number(parts.hostname.split('.').some((label) => label.startsWith('xn--'))),
    hasNonDefaultPort: Number(Boolean(url.port)),
    suspiciousWordCount: (value.match(URL_KEYWORDS) ?? []).length,
  };
}
