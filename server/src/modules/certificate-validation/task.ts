import ipaddr from 'ipaddr.js';
import { parseTarget, PolicyError, resolvePublic, systemResolver, type Resolver } from '../web-security/network/policy.js';
import { connectTls, type Connector } from './connect.js';
import { evaluateCertificate, type CertificateDetails, type CertificateFinding } from './evaluate.js';

export type CertificateStatus = 'ok' | 'skipped' | 'blocked' | 'error';

export interface CertificateValidationResult {
  status: CertificateStatus;
  /** true / false when a certificate was judged, null when it could not be (skipped, blocked, error). */
  valid: boolean | null;
  reason?: string;
  trustError?: string;
  findings: CertificateFinding[];
  details?: CertificateDetails;
  coverageLimitations?: string[];
}

export type CertificateTask = (input: unknown) => Promise<CertificateValidationResult>;

export const COVERAGE_LIMITATIONS = [
  'Revocation (CRL/OCSP) is not checked',
  'Only the leaf certificate is evaluated, not intermediates',
  'Signature algorithm and Certificate Transparency are not checked',
];

export interface CertificateTaskOptions {
  resolver?: Resolver;
  connect?: Connector;
  timeoutMs?: number;
  now?: () => Date;
}

const empty = (status: CertificateStatus, reason: string): CertificateValidationResult => ({ status, valid: null, reason, findings: [] });

function describe(error: unknown): string {
  const code = error && typeof error === 'object' && 'code' in error ? String((error as { code: unknown }).code) : undefined;
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return 'Host could not be resolved';
  if (code === 'ECONNREFUSED') return 'Connection refused';
  if (code === 'ETIMEDOUT') return 'Connection timed out';
  if (code === 'ECONNRESET') return 'Connection reset by server';
  if (code === 'NO_CERTIFICATE') return 'Server presented no certificate';
  return code ? `TLS connection failed (${code})` : 'TLS connection failed';
}

/**
 * Networks with NAT64/DNS64 (common on mobile data) add a synthetic 64:ff9b:: address next to the real
 * IPv4 one for IPv4-only hosts. We never connect to those, so drop them and still require every
 * remaining answer to be public. If nothing else is left they stay and the guard blocks them.
 */
function withoutNat64(resolver: Resolver): Resolver {
  return async (hostname) => {
    const answers = await resolver(hostname);
    const kept = answers.filter(({ address }) => {
      try { return ipaddr.parse(address).range() !== 'rfc6052'; } catch { return true; }
    });
    return kept.length ? kept : answers;
  };
}

/** Builds the pipeline task. Never throws: every failure becomes a structured result with valid: null. */
export function createCertificateTask(options: CertificateTaskOptions = {}): CertificateTask {
  const { connect = connectTls, timeoutMs = 8000, now = () => new Date() } = options;
  const resolver = withoutNat64(options.resolver ?? systemResolver);
  return async (input) => {
    try {
      const raw = input && typeof input === 'object' ? (input as { url?: unknown }).url : undefined;
      if (typeof raw !== 'string') return empty('error', 'Input must contain a url string');
      let url: URL;
      try { url = new URL(raw); } catch { return empty('error', 'Invalid URL'); }
      if (url.protocol === 'http:') return empty('skipped', 'HTTP URL: there is no TLS certificate to check');
      url.hash = '';
      try { parseTarget(url.href); } catch (error) {
        if (error instanceof PolicyError) return empty('blocked', error.message);
        throw error;
      }
      const hostname = url.hostname.replace(/^\[|\]$/g, '');
      let address: Awaited<ReturnType<typeof resolvePublic>>;
      try { address = await resolvePublic(url, resolver); } catch (error) {
        if (error instanceof PolicyError) return empty('blocked', error.message);
        return empty('error', describe(error));
      }
      let peer: Awaited<ReturnType<Connector>>;
      try {
        peer = await connect({ hostname, address: address.address, port: Number(url.port) || 443 }, timeoutMs);
      } catch (error) { return empty('error', describe(error)); }
      const report = evaluateCertificate(peer.cert, { hostname, now: now(), trustError: peer.authorizationError });
      return {
        status: 'ok',
        valid: report.valid,
        ...(peer.authorizationError ? { trustError: peer.authorizationError } : {}),
        findings: report.findings,
        details: report.details,
        coverageLimitations: [...COVERAGE_LIMITATIONS],
      };
    } catch {
      return empty('error', 'Certificate validation failed unexpectedly');
    }
  };
}

export const validateCertificate: CertificateTask = createCertificateTask();