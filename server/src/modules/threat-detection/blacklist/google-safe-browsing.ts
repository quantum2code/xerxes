import { createSafeBrowsingFamilyFetch } from './google-provider-transport.js';
import { isRecord, providerUrl } from './provider-http.js';
import { createGoogleJsonClient, GOOGLE_THREAT_TYPES, invalidGoogleResponse, isGoogleThreatType } from './google-provider.js';
import type { GoogleThreatType } from './google-provider.js';
import type { BlacklistProvider, GoogleSafeBrowsingProviderOptions } from './types.js';

const PROVIDER = 'Google Safe Browsing';
const PLATFORMS = new Set(['ANY_PLATFORM', 'ALL_PLATFORMS', 'WINDOWS', 'LINUX', 'ANDROID', 'OSX', 'IOS', 'CHROME']);
export const GOOGLE_SAFE_BROWSING_ADVISORY =
  'Advisory provided by Google: https://developers.google.com/safe-browsing/v4/advisory';

function parseThreatMatch(match: unknown, expectedUrl: string): GoogleThreatType {
  if (!isRecord(match) || !isGoogleThreatType(match.threatType)
    || typeof match.platformType !== 'string' || !PLATFORMS.has(match.platformType)
    || match.threatEntryType !== 'URL' || !isRecord(match.threat) || typeof match.threat.url !== 'string'
    || typeof match.cacheDuration !== 'string' || !/^\d+(?:\.\d{1,9})?s$/.test(match.cacheDuration)
    || !Number.isFinite(Number(match.cacheDuration.slice(0, -1)))) {
    throw invalidGoogleResponse(PROVIDER);
  }

  let matchedUrl: string;
  try {
    matchedUrl = providerUrl(match.threat.url);
  } catch {
    throw invalidGoogleResponse(PROVIDER);
  }
  if (matchedUrl !== expectedUrl) throw invalidGoogleResponse(PROVIDER);
  return match.threatType;
}

/** Non-commercial Safe Browsing v4 Lookup API. No caching, retries, submissions, or implicit keys. */
export function createGoogleSafeBrowsingProvider(options: GoogleSafeBrowsingProviderOptions): BlacklistProvider {
  const requestJson = createGoogleJsonClient(PROVIDER, options, createSafeBrowsingFamilyFetch);
  return {
    name: 'google-safe-browsing',
    check: async (input, { signal }) => {
      if (signal.aborted) throw new Error('Google Safe Browsing request aborted');
      const url = providerUrl(input);
      const response = await requestJson(
        'https://safebrowsing.googleapis.com/v4/threatMatches:find', {
          method: 'POST', signal,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            client: { clientId: 'xerxes', clientVersion: '1.0.0' },
            threatInfo: {
              threatTypes: GOOGLE_THREAT_TYPES,
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url }],
            },
          }),
        });
      if (Object.keys(response).length === 0) return { matched: false };
      if (!Array.isArray(response.matches)) throw invalidGoogleResponse(PROVIDER);
      if (response.matches.length === 0) return { matched: false };
      const types = new Set(response.matches.map((match) => parseThreatMatch(match, url)));
      const categories = GOOGLE_THREAT_TYPES.filter((type) => types.has(type));
      return { matched: true, details: `Potentially unsafe URL: ${categories.join(', ')}. ${GOOGLE_SAFE_BROWSING_ADVISORY}. `
        + 'Learn more: https://www.antiphishing.org/; https://developers.google.com/search/docs/monitor-debug/security/malware; '
        + 'https://www.google.com/about/unwanted-software-policy.html' };
    },
  };
}
