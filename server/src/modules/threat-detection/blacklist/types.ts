export interface BlacklistSnapshot {
  source: string;
  /** Caller-maintained ISO 8601 timestamp; snapshots are never downloaded or refreshed here. */
  updatedAt: string;
  urls?: readonly string[];
  domains?: readonly string[];
}

export interface BlacklistProviderResult {
  matched: boolean;
  details?: string;
}


export interface PhishTankProviderOptions {
  /** Optional, but keyless requests have lower service rate limits. */
  apiKey?: string;
  /** Descriptive application identity; defaults to phishtank/xerxes. */
  userAgent?: string;
  /** Trusted HTTP seam for offline tests; defaults to the native fetch implementation. */
  fetch?: typeof globalThis.fetch;
}

export interface GoogleProviderOptions {
  /** Server-side Google API key with the chosen service enabled. Required. */
  apiKey: string;
  /** Optional DNS family override for the fixed Google endpoint, not submitted URLs. */
  addressFamily?: 4 | 6;
  /** Trusted HTTP seam for offline tests; defaults to native fetch. */
  fetch?: typeof globalThis.fetch;
}

export type GoogleWebRiskProviderOptions = GoogleProviderOptions;

/** Google Safe Browsing is free for non-commercial use only. */
export type GoogleSafeBrowsingProviderOptions = GoogleProviderOptions;

export interface BlacklistProvider {
  name: string;
  /** Receives the full canonical URL, including potentially sensitive path/query data. Honor signal for cleanup. */
  check: (url: string, context: { signal: AbortSignal }) => Promise<BlacklistProviderResult>;
}

export interface BlacklistOptions {
  snapshots?: readonly BlacklistSnapshot[];
  providers?: readonly BlacklistProvider[];
  /** Independent deadline for each provider, integer 1–120000 ms (default 5000). */
  timeoutMs?: number;
}

export interface BlacklistSource {
  source: string;
  kind: 'snapshot' | 'provider';
}

export interface BlacklistMatch extends BlacklistSource {
  details?: string;
}

export interface BlacklistError {
  source: string;
  kind: 'provider';
  code: 'timeout' | 'provider_error';
  message: string;
}

export interface BlacklistResult {
  /** no_match only means no configured source matched; it does not establish that a URL is benign. */
  status: 'matched' | 'no_match' | 'unknown';
  matches: BlacklistMatch[];
  /** All attempted sources, including providers that failed or timed out, in configuration order. */
  checkedSources: BlacklistSource[];
  errors: BlacklistError[];
  /** Dates are reported without imposing a freshness policy. */
  snapshots: { source: string; updatedAt: string }[];
}

export type BlacklistChecker = (input: string) => Promise<BlacklistResult>;
