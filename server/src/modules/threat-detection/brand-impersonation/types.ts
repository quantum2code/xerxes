export interface BrandDefinition {
  name: string;
  /** Official registrable domains, including any legitimate regional/alternate domains. */
  domains: readonly string[];
}

export interface BrandImpersonationFinding {
  brand: string;
  reason: 'unicode_confusable' | 'domain_typo' | 'brand_in_domain' | 'deceptive_subdomain';
  observed: string;
  officialDomains: string[];
  editDistance?: number;
}

export interface BrandImpersonationResult {
  normalizedUrl: string;
  registrableDomain: string | null;
  brandsChecked: number;
  findings: BrandImpersonationFinding[];
}
