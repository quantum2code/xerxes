import { fetchProviderJson, isRecord, validateProviderApiKey } from './provider-http.js';
import type { GoogleProviderOptions } from './types.js';

export const GOOGLE_THREAT_TYPES = ['SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE'] as const;
export type GoogleThreatType = typeof GOOGLE_THREAT_TYPES[number];

export function isGoogleThreatType(value: unknown): value is GoogleThreatType {
  return GOOGLE_THREAT_TYPES.some((type) => type === value);
}

export function invalidGoogleResponse(provider: string): Error {
  return new Error(`${provider} returned an invalid provider response`);
}

/** Snapshot credentials/transport once; service modules retain their own request and response schemas. */
export function createGoogleJsonClient(
  provider: string,
  options: GoogleProviderOptions,
  familyFetch: (family: 4 | 6) => typeof globalThis.fetch,
) {
  const { apiKey, addressFamily } = options;
  validateProviderApiKey(apiKey, provider);
  if (addressFamily !== undefined && addressFamily !== 4 && addressFamily !== 6) {
    throw new TypeError(`${provider} addressFamily must be 4 or 6`);
  }
  const fetchImpl = options.fetch ?? (addressFamily === undefined ? globalThis.fetch : familyFetch(addressFamily));

  return async (endpoint: string, init: RequestInit): Promise<Record<string, unknown>> => {
    const headers = new Headers(init.headers);
    headers.set('accept', 'application/json');
    headers.set('x-goog-api-key', apiKey);
    const response = await fetchProviderJson(provider, endpoint, { ...init, headers }, fetchImpl);
    if (!isRecord(response) || 'error' in response) throw invalidGoogleResponse(provider);
    return response;
  };
}
