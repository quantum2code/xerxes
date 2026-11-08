import ipaddr from 'ipaddr.js';
import { parseTlsTarget, PolicyError, resolvePublic, systemResolver, type Resolver } from './guard.js';
import { connectTls, type Connector } from './connect.js';
import { categorize } from './categories.js';
import { evaluateChain, type ChainCertificate } from './chain.js';
import { evaluateNegotiated } from './negotiated.js';
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
  /** Every certificate the server presented, with per-certificate facts. */
  chain?: { complete: boolean; certificates: ChainCertificate[] };
  coverageLimitations?: string[];
  /** Protocol and cipher suite the server picked for this probe. */
  tls?: { protocol: string; cipher?: string };
}

export type CertificateTask = (input: unknown) => Promise<CertificateValidationResult>;

export const COVERAGE_LIMITATIONS = [
  'Revocation (CRL/OCSP) is not checked',
  'Certificate Transparency is not checked',
  'Only the negotiated TLS version and cipher are examined, not every one the server supports',
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
      try { parseTlsTarget(url.href); } catch (error) {
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
      const at = now();
      const report = evaluateCertificate(peer.cert, { hostname, now: at, trustError: peer.authorizationError });
      const chain = peer.chain ? evaluateChain(peer.chain, { now: at, trustError: peer.authorizationError }) : undefined;
      // A precise chain finding replaces the leaf's generic untrusted-chain one for the same handshake error.
      const explained = chain?.findings.some((f) => f.id === 'chain.incomplete' || f.id === 'chain.unknown_issuer');
      const findings = [...report.findings.filter((f) => !(explained && f.id === 'cert.untrusted_chain')), ...(chain?.findings ?? []), ...evaluateNegotiated({ protocol: peer.protocol, cipher: peer.cipher })].map(categorize);
      return {
        status: 'ok',
        valid: !findings.some((finding) => finding.severity === 'high' || finding.severity === 'critical'),
        ...(peer.authorizationError ? { trustError: peer.authorizationError } : {}),
        findings,
        details: report.details,
        ...(chain ? { chain: { complete: chain.complete, certificates: chain.certificates } } : {}),
        ...(peer.protocol ? { tls: { protocol: peer.protocol, cipher: peer.cipher } } : {}),
        coverageLimitations: [...COVERAGE_LIMITATIONS],
      };
    } catch {
      return empty('error', 'Certificate validation failed unexpectedly');
    }
  };
}

export const validateCertificate: CertificateTask = createCertificateTask();