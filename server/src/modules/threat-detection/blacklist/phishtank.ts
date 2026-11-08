import { fetchProviderJson, isRecord, providerUrl, validateProviderApiKey } from './provider-http.js';
import type { BlacklistProvider, PhishTankProviderOptions } from './types.js';

function responseFlag(value: unknown): boolean {
  if (value === true || value === 'y') return true;
  if (value === false || value === 'n') return false;
  throw new Error('PhishTank returned an invalid provider response');
}

export function createPhishTankProvider(options: PhishTankProviderOptions = {}): BlacklistProvider {
  const apiKey = options.apiKey;
  if (apiKey !== undefined) validateProviderApiKey(apiKey, 'PhishTank');
  const userAgent = options.userAgent === undefined ? 'phishtank/xerxes' : options.userAgent;
  if (typeof userAgent !== 'string' || !userAgent.trim() || /[^\u0020-\u007e]/u.test(userAgent)) {
    throw new TypeError('PhishTank userAgent must be nonempty printable ASCII without control characters');
  }
  const fetchImpl = options.fetch ?? globalThis.fetch;

  return {
    name: 'phishtank',
    check: async (input, { signal }) => {
      if (signal.aborted) throw new Error('PhishTank request aborted');
      const body = new URLSearchParams({ url: providerUrl(input), format: 'json' });
      if (apiKey !== undefined) body.set('app_key', apiKey);
      const response = await fetchProviderJson('PhishTank', 'https://checkurl.phishtank.com/checkurl/', {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-type': 'application/x-www-form-urlencoded',
          'user-agent': userAgent,
        },
        body,
        signal,
      }, fetchImpl);
      if (!isRecord(response) || !isRecord(response.results)
        || typeof response.results.in_database !== 'boolean') {
        throw new Error('PhishTank returned an invalid provider response');
      }
      const results = response.results;
      if (!results.in_database) return { matched: false };
      const verified = responseFlag(results.verified);
      const valid = responseFlag(results.valid);
      if (!verified) throw new Error('PhishTank returned an incomplete or unverified provider response');
      if (!valid) return { matched: false };
      return { matched: true, details: 'Verified phishing URL in PhishTank' };
    },
  };
}
