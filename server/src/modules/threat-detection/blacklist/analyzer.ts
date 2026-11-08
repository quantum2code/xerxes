import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { parse } from 'tldts';
import { canonicalLookupUrl, normalizedHostname } from '../shared/url.js';

import type {
  BlacklistChecker,
  BlacklistError,
  BlacklistMatch,
  BlacklistOptions,
  BlacklistProvider,
  BlacklistResult,
  BlacklistSource,
} from './types.js';

export type {
  BlacklistChecker,
  BlacklistError,
  BlacklistMatch,
  BlacklistOptions,
  BlacklistProvider,
  BlacklistProviderResult,
  BlacklistResult,
  BlacklistSnapshot,
  BlacklistSource,
} from './types.js';

function requireObject(value: unknown, label: string): void {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
}

function requireName(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || value.trim().length === 0 || value !== value.trim()) {
    throw new TypeError(`${label} must be a non-empty string without surrounding whitespace`);
  }
}

function requireArray(value: unknown, label: string): void {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array`);
}

function validateDate(value: string): void {
  // Require a timestamp with a timezone, and reject dates Date.parse would silently roll over.
  const parts = typeof value === 'string'
    ? /^(\d{4})-(\d{2})-(\d{2})T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(value)
    : null;
  if (!parts || !Number.isFinite(Date.parse(value))) {
    throw new TypeError('Snapshot updatedAt must be an ISO 8601 timestamp with a timezone');
  }
  const month = Number(parts[2]);
  const day = Number(parts[3]);
  const days = new Date(`${parts[1]}-${parts[2]}-01T00:00:00Z`);
  days.setUTCMonth(days.getUTCMonth() + 1, 0);
  if (month < 1 || month > 12 || day < 1 || day > days.getUTCDate()) {
    throw new TypeError('Snapshot updatedAt contains an invalid calendar date');
  }
}

function domainKey(input: string): { hostname: string; isIp: boolean } {
  requireName(input, 'Snapshot domain');
  const host = input.toLowerCase().replace(/\.$/u, '');
  if (isIP(host)) {
    // URL serialization gives equivalent IPv6 spellings the same key.
    return {
      hostname: normalizedHostname(new URL(`http://${isIP(host) === 6 ? `[${host}]` : host}/`)),
      isIp: true,
    };
  }
  if (/[\s\u0000-\u0020\u007f/:@?#\\*%\[\]]/u.test(host)) {
    throw new TypeError('Snapshot domains must contain only a hostname, without URL syntax or wildcards');
  }
  const ascii = domainToASCII(host);
  const labels = ascii.split('.');
  if (!ascii || ascii.length > 253 || labels.some((label) =>
    label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))) {
    throw new TypeError('Invalid snapshot hostname');
  }
  // Reject noncanonical numeric IPv4 forms rather than letting URL parsing reinterpret them.
  if (isIP(ascii) || /^[\d.]+$/u.test(ascii)) throw new TypeError('Invalid snapshot IP address');
  const parsed = parse(ascii, { allowPrivateDomains: true, validateHostname: true });
  if (!parsed.domain || !parsed.hostname || parsed.isIp) {
    throw new TypeError('Snapshot domains must be registrable hosts, not bare public suffixes');
  }
  return { hostname: ascii, isIp: false };
}

async function checkProvider(
  provider: BlacklistProvider,
  url: string,
  timeoutMs: number,
): Promise<{ match?: BlacklistMatch; error?: BlacklistError }> {
  const controller = new AbortController();
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      const error = new Error(`Provider exceeded ${timeoutMs} ms deadline`);
      reject(error);
      controller.abort(error);
    }, timeoutMs);
  });
  try {
    // Deferring invocation captures synchronous throws as provider errors as well.
    const response = await Promise.race([
      Promise.resolve().then(() => provider.check(url, { signal: controller.signal })),
      deadline,
    ]);
    if (!response || typeof response.matched !== 'boolean'
      || (response.details !== undefined && typeof response.details !== 'string')) {
      throw new TypeError('Provider must return { matched: boolean, details?: string }');
    }
    if (!response.matched) return {};

    const match: BlacklistMatch = { source: provider.name, kind: 'provider' };
    if (response.details !== undefined) {
      match.details = response.details;
    }
    return { match };
  } catch (error) {
    let message = 'Provider failed';
    if (error instanceof Error) {
      message = error.message;
    } else if (typeof error === 'string') {
      message = error;
    }
    return { error: {
      source: provider.name,
      kind: 'provider',
      code: timedOut ? 'timeout' : 'provider_error',
      message,
    } };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Creates an independent blacklist checker; no feeds, default providers, API keys, or network calls
 * are built in. Snapshots are caller maintained and copied/normalized at creation. Provider functions
 * are trusted, caller-supplied integrations and receive the full URL, including potentially sensitive
 * query parameters. Credential-bearing URLs are rejected, even for snapshot-only checks.
 *
 * A no_match result is NOT evidence that a URL is benign. No sources, or any provider failure without
 * a match, yields unknown. Matches survive other providers' failures. Configuration errors throw at
 * creation; invalid input URLs reject the returned promise. Providers run concurrently with separate
 * deadlines; timeout bounds waiting even if a provider ignores its AbortSignal (it cannot stop its work).
 */
export function createBlacklistChecker(options: BlacklistOptions = {}): BlacklistChecker {
  requireObject(options, 'Blacklist options');
  const timeoutMs = options.timeoutMs === undefined ? 5000 : options.timeoutMs;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000) {
    throw new TypeError('timeoutMs must be an integer between 1 and 120000');
  }
  if (options.snapshots !== undefined) requireArray(options.snapshots, 'snapshots');
  if (options.providers !== undefined) requireArray(options.providers, 'providers');
  const snapshots = Array.from(options.snapshots ?? [], (snapshot) => {
    requireObject(snapshot, 'Snapshot');
    requireName(snapshot.source, 'Snapshot source');
    validateDate(snapshot.updatedAt);
    if (snapshot.urls !== undefined) requireArray(snapshot.urls, 'Snapshot urls');
    if (snapshot.domains !== undefined) requireArray(snapshot.domains, 'Snapshot domains');
    return {
      source: snapshot.source,
      updatedAt: snapshot.updatedAt,
      urls: new Set(Array.from(snapshot.urls ?? [], canonicalLookupUrl)),
      domains: Array.from(snapshot.domains ?? [], domainKey),
    };
  });
  const providers = Array.from(options.providers ?? [], (provider) => {
    requireObject(provider, 'Provider');
    requireName(provider.name, 'Provider name');
    if (typeof provider.check !== 'function') throw new TypeError('Provider check must be a function');
    return { name: provider.name, check: provider.check };
  });

  return async (input) => {
    const url = canonicalLookupUrl(input);
    const hostname = normalizedHostname(new URL(url));
    const matches: BlacklistMatch[] = [];
    const checkedSources: BlacklistSource[] = [];
    for (const snapshot of snapshots) {
      checkedSources.push({ source: snapshot.source, kind: 'snapshot' });
      if (snapshot.urls.has(url) || snapshot.domains.some((domain) =>
        hostname === domain.hostname || (!domain.isIp && hostname.endsWith(`.${domain.hostname}`)))) {
        matches.push({ source: snapshot.source, kind: 'snapshot' });
      }
    }
    const outcomes = await Promise.all(providers.map((provider) => checkProvider(provider, url, timeoutMs)));
    const errors: BlacklistError[] = [];
    for (const [index, outcome] of outcomes.entries()) {
      checkedSources.push({ source: providers[index]!.name, kind: 'provider' });
      if (outcome.match) matches.push(outcome.match);
      if (outcome.error) errors.push(outcome.error);
    }
    let status: BlacklistResult['status'];
    if (matches.length > 0) {
      status = 'matched';
    } else if (errors.length > 0 || checkedSources.length === 0) {
      status = 'unknown';
    } else {
      status = 'no_match';
    }
    return {
      status,
      matches,
      checkedSources,
      errors,
      snapshots: snapshots.map(({ source, updatedAt }) => ({ source, updatedAt })),
    };
  };
}
