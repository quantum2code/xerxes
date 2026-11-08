import { isRecord, providerUrl } from './provider-http.js';
import { createGoogleJsonClient, GOOGLE_THREAT_TYPES, invalidGoogleResponse, isGoogleThreatType } from './google-provider.js';
import type { BlacklistProvider, GoogleWebRiskProviderOptions } from './types.js';
import { createWebRiskFamilyFetch } from './google-provider-transport.js';

const PROVIDER = 'Google Web Risk';

/** Google Web Risk Lookup API. No submissions, caching, retries, or implicit credential discovery. */
export function createGoogleWebRiskProvider(options: GoogleWebRiskProviderOptions): BlacklistProvider {
  const requestJson = createGoogleJsonClient(PROVIDER, options, createWebRiskFamilyFetch);
  return {
    name: 'google-web-risk',
    check: async (input, { signal }) => {
      if (signal.aborted) throw new Error('Google Web Risk request aborted');
      const endpoint = new URL('https://webrisk.googleapis.com/v1/uris:search');
      endpoint.searchParams.set('uri', providerUrl(input));
      for (const type of GOOGLE_THREAT_TYPES) endpoint.searchParams.append('threatTypes', type);
      const response = await requestJson(endpoint.href, { method: 'GET', signal });
      // Only the documented empty object means no match, not an error/unknown envelope.
      if (Object.keys(response).length === 0) return { matched: false };
      const threat = response.threat;
      if (!isRecord(threat) || !Array.isArray(threat.threatTypes) || !threat.threatTypes.length
        || !threat.threatTypes.every(isGoogleThreatType)
        || typeof threat.expireTime !== 'string'
        || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(threat.expireTime)
        || !Number.isFinite(Date.parse(threat.expireTime))) {
        throw invalidGoogleResponse(PROVIDER);
      }
      // Emit only validated enum names, not provider-supplied URLs, errors, or other metadata.
      const matchedTypes = threat.threatTypes;
      const types = GOOGLE_THREAT_TYPES.filter((type) => matchedTypes.includes(type));
      return { matched: true, details: `Google Web Risk match: ${types.join(', ')}` };
    },
  };
}
