import type { UrlFeatures } from '../shared/url-features.js';

export interface UrlSignal {
  code: 'http' | 'ip_host' | 'credentials' | 'punycode' | 'non_default_port'
    | 'long_url' | 'many_subdomains' | 'many_hyphens' | 'sensitive_keywords' | 'encoded_characters'
    | 'local_hostname' | 'unusual_ip_notation';

  location: 'scheme' | 'hostname' | 'userinfo' | 'port' | 'url' | 'path' | 'query' | 'fragment';
  description: string;
  /** Only bounded structural evidence, never the username/password or entire submitted URL. */
  evidence: { value: string | number; threshold?: number; matches?: string[] };
}

export interface BasicUrlAnalysis {
  /** Full serialized URL; potentially sensitive. Do not log the entire result indiscriminately. */
  normalizedUrl: string;
  /** User information removed. Path, query, and fragment may still contain secrets. */
  displayUrl: string;
  hostname: string;
  unicodeHostname: string;
  registrableDomain: string | null;
  publicSuffix: string | null;
  subdomain: string | null;
  features: UrlFeatures;
  signals: UrlSignal[];
}
