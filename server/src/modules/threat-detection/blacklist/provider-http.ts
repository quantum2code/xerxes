export { canonicalLookupUrl as providerUrl } from '../shared/url.js';

export function validateProviderApiKey(value: string, provider: string): void {
  if (typeof value !== 'string' || !value || /[\s\u0000-\u0020\u007f]/u.test(value)) {
    throw new TypeError(`${provider} API key must be a nonempty token without whitespace or control characters`);
  }
}

/** Only status codes are exposed: service bodies and network errors can echo URLs or credentials. */
export async function fetchProviderJson(
  provider: string,
  endpoint: string,
  init: RequestInit,
  fetchImpl: typeof globalThis.fetch,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetchImpl(endpoint, { ...init, redirect: 'error' });
  } catch {
    throw new Error(`${provider} request failed`);
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    if (response.status === 429 || response.status === 509) {
      throw new Error(`${provider} rate limit exceeded (HTTP ${response.status})`);
    }
    if (response.status === 401 || response.status === 403) {
      throw new Error(`${provider} authentication or access denied (HTTP ${response.status})`);
    }
    throw new Error(`${provider} request failed (HTTP ${response.status})`);
  }
  try {
    return await response.json();
  } catch {
    throw new Error(`${provider} returned invalid JSON`);
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
