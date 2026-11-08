import type { AddressInfo } from '../../shared/network/policy.js';

export type AnalysisStatus = 'completed' | 'partial' | 'blocked' | 'failed';
export const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'] as const;
export type RecordType = typeof recordTypes[number];
export interface AnalysisError {
  stage: 'input' | 'dns' | 'http' | 'analysis';
  code: string;
  message: string;
  retryable: boolean;
  recordType?: RecordType;
}
export interface UrlData {
  original: string;
  normalized: string;
  scheme: 'http' | 'https';
  hostname: string;
  asciiHostname: string;
  unicodeHostname: string;
  port: number;
  explicitPort: boolean;
  path: string;
  queryParameterNames: string[];
  queryParameterCount: number;
  hasFragment: boolean;
  domain: string | null;
  publicSuffix: string | null;
  subdomain: string | null;
  domainLabels: string[];
  isIpAddress: boolean;
  ipVersion: 4 | 6 | null;
}
export interface UrlFeatures {
  urlLength: number; hostnameLength: number; pathLength: number; subdomainCount: number; queryParameterCount: number;
  dotCount: number; hyphenCount: number; digitCount: number; specialCharacterCount: number;
  hasIpAddress: boolean; hasPunycode: boolean; hasPercentEncoding: boolean; unusualPort: boolean;
  nonCanonicalIpv4: boolean; repeatedSlashes: boolean; repeatedEncoding: boolean; embeddedUrlSyntax: boolean;
  entropyBitsPerCharacter: number;
  terms: Record<'login' | 'verify' | 'account' | 'secure' | 'update', boolean>;
}
export interface DnsQueryResult {
  status: 'completed' | 'absent' | 'failed' | 'skipped'; durationMs: number; truncated: boolean; error?: AnalysisError;
}
export interface DnsAddress { address: string; ttl: number | null; network: AddressInfo; }
export interface DnsResult {
  status: 'completed' | 'partial' | 'failed' | 'skipped'; durationMs: number;
  a: DnsAddress[]; aaaa: DnsAddress[]; cname: string[]; mx: { exchange: string; priority: number }[]; ns: string[];
  txt: { segments: string[]; byteLength: number; kind: 'spf' | 'dmarc' | 'dkim' | 'verification' | 'other' }[];
  queries: Record<RecordType, DnsQueryResult>; errors: AnalysisError[];
}
export interface RedirectHop {
  url: string; statusCode: number; target: string; crossesRegistrableDomain: boolean | null; followed: boolean;
}
export interface HttpResult {
  status: 'completed' | 'failed' | 'blocked' | 'timed_out' | 'cancelled' | 'skipped';
  statusCode: number | null; finalUrl: string | null; method: 'HEAD' | 'GET' | null;
  redirects: RedirectHop[]; redirectCount: number; requestCount: number; responseTimeMs: number;
  contentType: string | null; contentLength: number | null; headers: Record<string, string>; errors: AnalysisError[];
}
export interface UrlAnalysisResult {
  module: 'urlAnalysis'; schemaVersion: '1.0'; status: AnalysisStatus; input: string; durationMs: number;
  url: UrlData | null; dns: DnsResult; http: HttpResult; features: UrlFeatures | null;
  errors: AnalysisError[]; limitations: string[];
}
export interface UrlAnalysisConfig {
  maxUrlLength: number; analysisTimeoutMs: number; dnsTimeoutMs: number; requestTimeoutMs: number;
  maxConcurrentAnalyses: number; dnsConcurrency: number; httpConcurrency: number;
  maxDnsRecords: number; maxDnsTextBytes: number; maxRedirects: number; maxHttpRequests: number;
  maxResponseBytes: number; maxHeaderBytes: number; userAgent: string; allowedPorts: number[];
}
