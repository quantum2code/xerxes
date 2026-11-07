import { z } from 'zod';
import type { UrlAnalysisConfig } from './types.js';

export function loadUrlAnalysisConfig(env: NodeJS.ProcessEnv = process.env): UrlAnalysisConfig {
  const integer = (key: string, fallback: number, maximum: number, minimum = 1) => {
    const parsed = z.coerce.number().int().min(minimum).max(maximum).safeParse(env[key] ?? fallback);
    if (!parsed.success) throw new Error(`Invalid ${key}`);
    return parsed.data;
  };
  const userAgent = env.URL_ANALYSIS_USER_AGENT ?? 'Xerxes-UrlAnalysis/1.0';
  if (!/^[\x20-\x7e]{1,128}$/.test(userAgent)) throw new Error('Invalid URL_ANALYSIS_USER_AGENT');
  const ports = z.array(z.coerce.number().int().min(1).max(65535)).min(1).max(32).safeParse((env.URL_ANALYSIS_ALLOWED_PORTS ?? '80,443').split(','));
  if (!ports.success) throw new Error('Invalid URL_ANALYSIS_ALLOWED_PORTS');
  return {
    maxUrlLength: 4096,
    analysisTimeoutMs: integer('URL_ANALYSIS_TIMEOUT_MS', 15000, 60000),
    dnsTimeoutMs: integer('URL_ANALYSIS_DNS_TIMEOUT_MS', 2000, 10000),
    requestTimeoutMs: integer('URL_ANALYSIS_REQUEST_TIMEOUT_MS', 4000, 15000),
    maxConcurrentAnalyses: integer('URL_ANALYSIS_MAX_CONCURRENT', 4, 32),
    dnsConcurrency: integer('URL_ANALYSIS_DNS_CONCURRENCY', 4, 32),
    httpConcurrency: integer('URL_ANALYSIS_HTTP_CONCURRENCY', 4, 32),
    maxDnsRecords: integer('URL_ANALYSIS_MAX_DNS_RECORDS', 32, 128),
    maxDnsTextBytes: integer('URL_ANALYSIS_MAX_DNS_TEXT_BYTES', 4096, 16384),
    maxRedirects: integer('URL_ANALYSIS_MAX_REDIRECTS', 5, 10, 0),
    maxHttpRequests: integer('URL_ANALYSIS_MAX_HTTP_REQUESTS', 12, 24),
    maxResponseBytes: integer('URL_ANALYSIS_MAX_RESPONSE_BYTES', 16384, 65536),
    maxHeaderBytes: integer('URL_ANALYSIS_MAX_HEADER_BYTES', 16384, 32768),
    allowedPorts: [...new Set(ports.data)], userAgent,
  };
}
