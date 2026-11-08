import { createGoogleSafeBrowsingProvider } from './modules/threat-detection/blacklist/index.js';
import { ZENODO_BRAND_CATALOG } from './modules/threat-detection/brand-impersonation/index.js';
import type { MlPhishingAnalyzer } from './modules/threat-detection/ml-phishing/index.js';
import type { ThreatDetectionPipelineOptions } from './pipelines/threat-detection-pipeline.js';

function parseAddressFamily(value: string | undefined): 4 | 6 | undefined {
  if (value === undefined) return undefined;
  if (value === '4') return 4;
  if (value === '6') return 6;
  throw new TypeError('GOOGLE_SAFE_BROWSING_ADDRESS_FAMILY must be 4 or 6');
}

/** Explicit application policy; standalone detector/pipeline defaults remain unchanged. */
export function createServerPipelineOptions(
  mlModule: MlPhishingAnalyzer,
  environment: NodeJS.ProcessEnv = process.env,
): ThreatDetectionPipelineOptions {
  // Legacy names are credential/routing aliases only; no requests go to Web Risk.
  const apiKey = environment.GOOGLE_SAFE_BROWSING_API_KEY ?? environment.GOOGLE_WEB_RISK_API_KEY;
  const addressFamily = parseAddressFamily(
    environment.GOOGLE_SAFE_BROWSING_ADDRESS_FAMILY ?? environment.GOOGLE_WEB_RISK_ADDRESS_FAMILY,
  );
  const providers = apiKey === undefined ? [] : [createGoogleSafeBrowsingProvider({ apiKey, addressFamily })];
  return {
    mlModule,
    brandImpersonation: { brands: ZENODO_BRAND_CATALOG },
    blacklist: { providers, timeoutMs: 5_000 },
    assessment: { trustedBlacklistSources: providers.map(({ name }) => name) },
  };
}
