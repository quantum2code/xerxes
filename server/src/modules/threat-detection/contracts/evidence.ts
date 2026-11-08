export const DETECTOR_MODULES = [
  'httpRedirectDetection', 'basicUrlAnalysis', 'mlPhishingDetection', 'blacklistCheck', 'brandImpersonation',
] as const;

export type DetectorModule = typeof DETECTOR_MODULES[number];

interface EvidenceSource {
  module: DetectorModule;
  hostname: string;
  /** Redirect observations must not corroborate findings about the submitted URL. */
  target: 'submitted' | 'redirect';
}

export type Evidence = EvidenceSource & (
  | {
      code: 'URL_STRUCTURE';
      signal: 'http' | 'ip_host' | 'credentials' | 'punycode' | 'non_default_port'
        | 'long_url' | 'many_subdomains' | 'many_hyphens' | 'encoded_characters'
        | 'local_hostname' | 'unusual_ip_notation';
      location: string;
      value: string | number;
      threshold?: number;
    }
  | { code: 'AUTH_KEYWORD'; location: string; keywords: string[] }
  | {
      code: 'REDIRECT_HOP'; fromHostname: string;
      fromScheme: 'http:' | 'https:'; toScheme: 'http:' | 'https:';
      crossDomain: boolean;
      /** True only when the destination returned a valid HTTP response. */
      followed: boolean;
    }
  | { code: 'BLACKLIST_MATCH'; source: string; sourceKind: 'snapshot' | 'provider' }
  | { code: 'ML_PREDICTION'; probability: number; threshold: number; modelId: string; trainedAt: string | null }
  | {
      code: 'BRAND_LOOKALIKE'; brand: string;
      reason: 'unicode_confusable' | 'domain_typo' | 'brand_in_domain' | 'deceptive_subdomain';
      officialDomains: string[]; editDistance?: number;
    }
);
