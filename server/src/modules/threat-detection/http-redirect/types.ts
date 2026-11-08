import type { LookupAddress } from 'node:dns';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type { RequestOptions as HttpsRequestOptions } from 'node:https';

export interface HttpRedirectResponse {
  statusCode: number;
  location?: string;
}

/** Trusted boundary: replacing this bypasses DNS/IP checks and socket pinning. Honor signal for cleanup. */
export type HttpRedirectTransport = (
  url: URL,
  context: { signal: AbortSignal },
) => Promise<HttpRedirectResponse>;

export type HttpRedirectLookup = (hostname: string) => Promise<readonly LookupAddress[]>;

/** Low-level trusted test seam; a replacement must honor lookup and TLS options to retain socket safety. */
export type HttpRedirectRequest = (
  url: URL,
  options: HttpsRequestOptions,
  onResponse: (response: IncomingMessage) => void,
) => ClientRequest;

export interface HttpRedirectOptions {
  /** Number of redirects followed, 0–50 (default 10); the initial request is not a redirect. */
  maxRedirects?: number;
  /** Total DNS + HTTP deadline for each hop, 1–120000 ms (default 5000). */
  timeoutMs?: number;
  transport?: HttpRedirectTransport;
}

export interface HttpRedirectHop {
  url: string;
  statusCode: number;
  /** Raw Location header, or null if absent. */
  location: string | null;
  /** Valid HTTP(S) destination, including targets stopped by safety, loop, or limit checks. */
  redirect?: {
    url: string;
    crossDomain: boolean;
    /** True only when the next hop returned a valid HTTP response. */
    followed: boolean;
  };
}

export interface HttpRedirectResult {
  status: 'complete' | 'blocked' | 'loop' | 'limit' | 'error';
  chain: HttpRedirectHop[];
  /** Last attempted URL (possibly blocked/unrequested); null when the input cannot be parsed. */
  finalUrl: string | null;
  /** Registrable-domain changes (hostname fallback for IPs/unknown suffixes), including blocked targets. */
  crossDomain: boolean;
  httpsDowngrade: boolean;
  error: { code: 'unsafe-url' | 'unsafe-address' | 'invalid-url' | 'invalid-options' | 'timeout' | 'network' | 'loop' | 'limit'; message: string } | null;
}
