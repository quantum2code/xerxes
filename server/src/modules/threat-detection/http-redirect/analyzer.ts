import { lookup as dnsLookup } from 'node:dns/promises';

import { request as httpRequest } from 'node:http';
import type { RequestOptions } from 'node:http';
import { request as httpsRequest } from 'node:https';

import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';
import { canonicalizeParsedUrl, domainParts, normalizedHostname, parseHttpUrl } from '../shared/url.js';

import type {
  HttpRedirectHop, HttpRedirectLookup, HttpRedirectOptions, HttpRedirectRequest,
  HttpRedirectResponse, HttpRedirectResult, HttpRedirectTransport,
} from './types.js';
export type {
  HttpRedirectHop, HttpRedirectLookup, HttpRedirectOptions, HttpRedirectRequest,
  HttpRedirectResponse, HttpRedirectResult, HttpRedirectTransport,
} from './types.js';

class RedirectError extends Error {
  constructor(readonly code: NonNullable<HttpRedirectResult['error']>['code'], message: string) {
    super(message);
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function checkUrl(url: URL): void {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new RedirectError('unsafe-url', 'Only HTTP and HTTPS URLs are allowed');
  }
  if (url.username || url.password || url.port) {
    throw new RedirectError('unsafe-url', 'Credentials and non-default ports are not allowed');
  }
}

function checkAddress(address: string, family: number): void {
  if (isIP(address) !== family || (family !== 4 && family !== 6)) {
    throw new RedirectError('unsafe-address', 'DNS returned an invalid IP address or family');
  }
  // process() converts IPv4-mapped IPv6 before range classification.
  if (ipaddr.process(address).range() !== 'unicast') {
    throw new RedirectError('unsafe-address', `Nonpublic IP address blocked: ${address}`);
  }
}

function abortable<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason ?? new Error('Request aborted'));
    if (signal.aborted) {
      reject(signal.reason ?? new Error('Request aborted'));
      // Consume a possible rejection from work even when already aborted.
      void work.catch(() => {});
      return;
    }
    signal.addEventListener('abort', abort, { once: true });
    work.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

/**
 * Creates a headers-only GET transport. All DNS answers must be unicast, including mapped IPv4;
 * the socket uses only a validated address while TLS verifies the original hostname.
 * lookup is a trusted resolver seam; request is a trusted socket seam for offline tests.
 * The caller supplies an AbortSignal deadline covering both DNS and HTTP (as detectHttpRedirects does).
 */
export function createSafeHttpRedirectTransport(options: {
  lookup?: HttpRedirectLookup;
  request?: HttpRedirectRequest;
} = {}): HttpRedirectTransport {
  const lookup = options.lookup ?? ((hostname: string) => dnsLookup(hostname, { all: true, verbatim: true }));
  const request: HttpRedirectRequest = options.request ?? ((url, requestOptions, onResponse) =>
    (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, requestOptions, onResponse));

  return async (url, { signal }) => {
    checkUrl(url);
    signal.throwIfAborted();
    const hostname = normalizedHostname(url);
    const literalFamily = isIP(hostname);
    const addresses = literalFamily
      ? [{ address: hostname, family: literalFamily }]
      : await abortable(lookup(hostname), signal);
    signal.throwIfAborted();
    if (addresses.length === 0) throw new RedirectError('unsafe-address', 'DNS returned no addresses');
    for (const address of addresses) checkAddress(address.address, address.family);
    const selected = addresses[0]!;
    const pinnedLookup: NonNullable<RequestOptions['lookup']> = (_hostname, lookupOptions, callback) => {
      if (lookupOptions.all) callback(null, [selected]);
      else callback(null, selected.address, selected.family);
    };

    return new Promise<HttpRedirectResponse>((resolve, reject) => {
      const req = request(url, {
        method: 'GET',
        agent: false,
        headers: { accept: '*/*' },
        hostname,
        family: selected.family,

        lookup: pinnedLookup,
        // Keep hostname verification/SNI tied to the URL, never the pinned address.
        servername: literalFamily ? undefined : hostname,
        rejectUnauthorized: true,
        signal,
      }, (response) => {
        const result = { statusCode: response.statusCode ?? 0, location: response.headers.location };
        // No data listeners, buffering, cookies, authentication, or body download.
        resolve(result);
        req.destroy();
      });
      req.on('error', reject);
      req.end();
    });
  };
}

function domainKey(url: URL): string {
  const parts = domainParts(url);
  return parts.domain ?? parts.hostname;
}

/**
 * Inspects only 301/302/303/307/308 redirects with Location, without fetching response bodies.
 * "complete" means the redirect chain ended, not that the destination is benign or returned 2xx.
 * All other statuses are inconclusive. Injected transports are trusted and bypass network guards;
 * URL scheme/credential/port checks and traversal deadlines still apply.
 * Invalid options/input are returned as explicit results rather than thrown.
 */
export async function detectHttpRedirects(input: string, options: HttpRedirectOptions = {}): Promise<HttpRedirectResult> {
  const result: HttpRedirectResult = {
    status: 'error', chain: [], finalUrl: null, crossDomain: false, httpsDowngrade: false, error: null,
  };
  try {
    const maxRedirects = options.maxRedirects ?? 10;
    const timeoutMs = options.timeoutMs ?? 5_000;
    if (!Number.isSafeInteger(maxRedirects) || maxRedirects < 0 || maxRedirects > 50
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) {
      throw new RedirectError('invalid-options', 'maxRedirects must be 0–50 and timeoutMs must be 1–120000 (integers)');
    }
    // Parse separately so unsupported protocols are classified as a safety block.
    let url: URL;
    try {
      url = new URL(input);
      result.finalUrl = url.href;
      checkUrl(url);
      url = canonicalizeParsedUrl(parseHttpUrl(input));
    } catch (error) {
      if (error instanceof RedirectError) throw error;
      throw new RedirectError('invalid-url', error instanceof Error ? error.message : String(error));
    }
    const transport = options.transport ?? createSafeHttpRedirectTransport();
    const seen = new Set<string>();
    let redirects = 0;
    while (true) {
      result.finalUrl = url.href;
      // Initial and redirect URLs are validated before entering the next iteration.
      seen.add(url.href);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(new RedirectError('timeout', 'Per-hop DNS/HTTP deadline exceeded')), timeoutMs);
      let response: HttpRedirectResponse;
      try {
        response = await abortable(Promise.resolve().then(() => transport(new URL(url), { signal: controller.signal })), controller.signal);
      } finally {
        clearTimeout(timer);
      }
      if (!Number.isInteger(response.statusCode) || response.statusCode < 100 || response.statusCode > 599) {
        throw new RedirectError('network', 'Transport returned an invalid HTTP status');
      }
      const previous = result.chain.at(-1)?.redirect;
      if (previous) previous.followed = true;
      const hop: HttpRedirectHop = { url: url.href, statusCode: response.statusCode, location: response.location ?? null };
      result.chain.push(hop);
      if (!REDIRECT_STATUSES.has(response.statusCode) || response.location === undefined) {
        result.status = 'complete';
        return result;
      }
      let next: URL;
      try {
        next = new URL(response.location, url);
      } catch {
        throw new RedirectError('invalid-url', 'Invalid redirect Location URL');
      }
      result.finalUrl = next.href;
      const crossDomain = domainKey(url) !== domainKey(next);
      result.crossDomain ||= crossDomain;
      result.httpsDowngrade ||= url.protocol === 'https:' && next.protocol === 'http:';
      // Retain observable HTTP(S) destinations even when traversal is blocked below.
      let target: URL | undefined;
      try {
        target = parseHttpUrl(next.href);
        hop.redirect = { url: target.href, crossDomain, followed: false };
      } catch { /* Invalid or unsupported destinations cannot produce URL evidence. */ }
      checkUrl(next);
      url = canonicalizeParsedUrl(target ?? parseHttpUrl(next.href));
      result.finalUrl = url.href;
      if (seen.has(url.href)) throw new RedirectError('loop', 'Redirect loop detected');
      if (redirects >= maxRedirects) throw new RedirectError('limit', 'Maximum redirects exceeded');
      redirects++;
    }
  } catch (error) {
    let failure: RedirectError;
    if (error instanceof RedirectError) {
      failure = error;
    } else {
      const message = error instanceof Error ? error.message : String(error);
      failure = new RedirectError('network', message);
    }

    if (failure.code === 'unsafe-url' || failure.code === 'unsafe-address') {
      result.status = 'blocked';
    } else if (failure.code === 'loop' || failure.code === 'limit') {
      result.status = failure.code;
    } else {
      result.status = 'error';
    }
    result.error = { code: failure.code, message: failure.message };
    return result;
  }
}
