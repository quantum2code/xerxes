import { X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import { signatureInfo } from './signature.js';

// Same shape as the shared "signal" used elsewhere in the pipeline: id + severity + message.
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface CertificateFinding {
  id: string;
  severity: Severity;
  message: string;
  /** validity | chain | crypto. Set by chain checks; others get it from categorize(). */
  category?: 'validity' | 'chain' | 'crypto';
}

export interface CertificateDetails {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysUntilExpiry: number;
  keyType: string | undefined;
  keyBits: number | undefined;
  selfSigned: boolean;
  subjectAltNames: string[];
  fingerprint256: string;
  signatureAlgorithm: string | undefined;
}

export interface CertificateReport {
  /** False when any finding is high or critical. Lower severities do not fail it. */
  valid: boolean;
  findings: CertificateFinding[];
  details: CertificateDetails;
}

export interface EvaluateOptions {
  /** Host the user asked for. Enables the hostname check. */
  hostname?: string;
  /** Injected so tests do not depend on the real clock. */
  now?: Date;
  /** Verification error code from the TLS handshake, e.g. UNABLE_TO_VERIFY_LEAF_SIGNATURE. */
  trustError?: string;
}

export const DAY_MS = 86_400_000;
export const EXPIRING_SOON_DAYS = 14;
const MAX_VALIDITY_DAYS = 398; // longest validity browsers accept for public certificates
export const MIN_RSA_BITS = 2048;
export const MIN_EC_BITS = 224;

const CURVE_BITS: Record<string, number> = {
  prime192v1: 192,
  secp224r1: 224,
  prime256v1: 256,
  secp256k1: 256,
  secp384r1: 384,
  secp521r1: 521,
};

// Handshake errors we already report with a clearer finding of our own.
const ALREADY_REPORTED = new Set([
  'CERT_HAS_EXPIRED',
  'CERT_NOT_YET_VALID',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
]);

export function keyInfo(cert: X509Certificate): { type: string | undefined; bits: number | undefined } {
  const key = cert.publicKey;
  const details = key.asymmetricKeyDetails;
  if (key.asymmetricKeyType === 'rsa') return { type: 'rsa', bits: details?.modulusLength };
  if (key.asymmetricKeyType === 'ec') {
    return { type: 'ec', bits: details?.namedCurve ? CURVE_BITS[details.namedCurve] : undefined };
  }
  return { type: key.asymmetricKeyType, bits: undefined };
}

/**
 * Deterministic checks on one certificate. No network, no clock (pass `now` to pin it).
 * Not covered yet: revocation, Certificate Transparency.
 */
export function evaluateCertificate(cert: X509Certificate, options: EvaluateOptions = {}): CertificateReport {
  const now = options.now ?? new Date();
  const validFrom = new Date(cert.validFrom);
  const validTo = new Date(cert.validTo);
  const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / DAY_MS);
  const validityDays = Math.round((validTo.getTime() - validFrom.getTime()) / DAY_MS);
  const { type, bits } = keyInfo(cert);
  const selfSigned = cert.checkIssued(cert) && cert.verify(cert.publicKey);
  const subjectAltNames = cert.subjectAltName ? cert.subjectAltName.split(', ') : [];
  const signature = signatureInfo(cert);

  const findings: CertificateFinding[] = [];
  const add = (id: string, severity: Severity, message: string) => findings.push({ id, severity, message });

  if (now > validTo) {
    add('cert.expired', 'high', `Certificate expired ${Math.floor((now.getTime() - validTo.getTime()) / DAY_MS)} day(s) ago`);
  } else if (now < validFrom) {
    add('cert.not_yet_valid', 'high', `Certificate is not valid until ${validFrom.toISOString()}`);
  } else if (daysUntilExpiry <= EXPIRING_SOON_DAYS) {
    add('cert.expiring_soon', 'low', `Certificate expires in ${daysUntilExpiry} day(s)`);
  }

  if (options.hostname) {
    const host = options.hostname.replace(/^\[|\]$/g, '');
    const matched = isIP(host) ? cert.checkIP(host) : cert.checkHost(host);
    if (!matched) add('cert.hostname_mismatch', 'high', `Certificate does not cover "${host}"`);
  }

  if (selfSigned) {
    add('cert.self_signed', 'high', 'Certificate is self-signed, so no authority vouches for it');
  }
  if (options.trustError && !ALREADY_REPORTED.has(options.trustError)) {
    add('cert.untrusted_chain', 'high', `Certificate chain is not trusted (${options.trustError})`);
  }

  if (type === 'rsa' && bits !== undefined && bits < MIN_RSA_BITS) {
    add('cert.weak_key', 'high', `RSA key is only ${bits} bits (minimum ${MIN_RSA_BITS})`);
  } else if (type === 'ec' && bits !== undefined && bits < MIN_EC_BITS) {
    add('cert.weak_key', 'high', `EC key is only ${bits} bits (minimum ${MIN_EC_BITS})`);
  }

  if (signature?.weak) {
    add('cert.weak_signature', 'high', 'Certificate is signed with ' + signature.name + ', which browsers no longer trust');
  }
  if (validityDays > MAX_VALIDITY_DAYS) {
    add('cert.long_validity', 'low', `Certificate is valid for ${validityDays} days (browsers accept at most ${MAX_VALIDITY_DAYS})`);
  }
  if (subjectAltNames.length === 0) {
    add('cert.no_san', 'medium', 'Certificate has no Subject Alternative Name; modern browsers reject it');
  }

  return {
    valid: !findings.some((f) => f.severity === 'high' || f.severity === 'critical'),
    findings,
    details: {
      subject: cert.subject.replaceAll('\n', ', '),
      issuer: cert.issuer.replaceAll('\n', ', '),
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      daysUntilExpiry,
      keyType: type,
      keyBits: bits,
      selfSigned,
      subjectAltNames,
      fingerprint256: cert.fingerprint256,
      signatureAlgorithm: signature?.name,
    },
  };
}
