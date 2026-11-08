import { X509Certificate } from 'node:crypto';
import { DAY_MS, EXPIRING_SOON_DAYS, keyInfo, MIN_EC_BITS, MIN_RSA_BITS, type CertificateFinding } from './evaluate.js';

export type ChainRole = 'leaf' | 'intermediate' | 'root';

export interface ChainCertificate {
  position: number;
  role: ChainRole;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysUntilExpiry: number;
  keyType: string | undefined;
  keyBits: number | undefined;
  isCa: boolean;
  selfSigned: boolean;
  fingerprint256: string;
}

export interface ChainReport {
  /** False when the handshake says the leaf's issuer (the intermediate) was not sent. */
  complete: boolean;
  certificates: ChainCertificate[];
  findings: CertificateFinding[];
}

export interface ChainOptions {
  now?: Date;
  /** Verification error code from the TLS handshake. */
  trustError?: string;
}

// UNABLE_TO_VERIFY_LEAF_SIGNATURE: the leaf's issuer was not sent and is not known locally (missing intermediate).
// UNABLE_TO_GET_ISSUER_CERT(_LOCALLY): the chain was sent but ends at an issuer this machine does not trust.
const MISSING_INTERMEDIATE = 'UNABLE_TO_VERIFY_LEAF_SIGNATURE';
const UNKNOWN_ISSUER = new Set(['UNABLE_TO_GET_ISSUER_CERT', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'SELF_SIGNED_CERT_IN_CHAIN']);

const label = (cert: X509Certificate) =>
  cert.subject.split('\n').find((line) => line.startsWith('CN='))?.slice(3) ?? cert.subject.replaceAll('\n', ', ');

function issuedBy(cert: X509Certificate, issuer: X509Certificate): boolean {
  try { return cert.checkIssued(issuer) && cert.verify(issuer.publicKey); } catch { return false; }
}

/** Checks every certificate the server presented (leaf first). The leaf's own checks live in evaluateCertificate. */
export function evaluateChain(chain: readonly X509Certificate[], options: ChainOptions = {}): ChainReport {
  const now = options.now ?? new Date();
  const findings: CertificateFinding[] = [];
  const add = (id: string, severity: CertificateFinding['severity'], message: string, category: 'chain' | 'crypto' = 'chain') =>
    findings.push({ id, severity, message, category });

  const certificates = chain.map((cert, position): ChainCertificate => {
    const selfSigned = issuedBy(cert, cert);
    const { type, bits } = keyInfo(cert);
    const validTo = new Date(cert.validTo);
    return {
      position,
      role: position === 0 ? 'leaf' : selfSigned && position === chain.length - 1 ? 'root' : 'intermediate',
      subject: cert.subject.replaceAll('\n', ', '),
      issuer: cert.issuer.replaceAll('\n', ', '),
      validFrom: new Date(cert.validFrom).toISOString(),
      validTo: validTo.toISOString(),
      daysUntilExpiry: Math.floor((validTo.getTime() - now.getTime()) / DAY_MS),
      keyType: type,
      keyBits: bits,
      isCa: cert.ca,
      selfSigned,
      fingerprint256: cert.fingerprint256,
    };
  });

  chain.forEach((cert, position) => {
    if (position === 0) return;
    const info = certificates[position]!;
    const name = `${info.role} certificate "${label(cert)}"`;
    if (now > new Date(info.validTo)) add('chain.expired', 'high', `${name} expired ${Math.floor((now.getTime() - new Date(info.validTo).getTime()) / DAY_MS)} day(s) ago`);
    else if (now < new Date(info.validFrom)) add('chain.not_yet_valid', 'high', `${name} is not valid until ${info.validFrom}`);
    else if (info.daysUntilExpiry <= EXPIRING_SOON_DAYS) add('chain.expiring_soon', 'low', `${name} expires in ${info.daysUntilExpiry} day(s)`);
    if (info.keyType === 'rsa' && info.keyBits !== undefined && info.keyBits < MIN_RSA_BITS) add('chain.weak_key', 'high', `${name} has a ${info.keyBits}-bit RSA key`, 'crypto');
    if (info.keyType === 'ec' && info.keyBits !== undefined && info.keyBits < MIN_EC_BITS) add('chain.weak_key', 'high', `${name} has a ${info.keyBits}-bit EC key`, 'crypto');
    if (!cert.ca) add('chain.not_a_ca', 'high', `${name} issues certificates but is not marked as a CA`);
  });

  for (let position = 0; position < chain.length - 1; position++) {
    if (!issuedBy(chain[position]!, chain[position + 1]!)) {
      add('chain.broken_link', 'high', `"${label(chain[position]!)}" was not issued by the next certificate in the chain ("${label(chain[position + 1]!)}")`);
    }
  }

  const complete = options.trustError !== MISSING_INTERMEDIATE;
  if (!complete) add('chain.incomplete', 'high', 'The server did not send the intermediate certificate(s) needed to build a trusted path; some clients will reject it');
  if (options.trustError && UNKNOWN_ISSUER.has(options.trustError) && chain.length) {
    const last = chain[chain.length - 1]!;
    add('chain.unknown_issuer', 'high', `The chain ends at "${last.issuer.split('\n').find((line) => line.startsWith('CN='))?.slice(3) ?? 'an unknown issuer'}", which is not in this machine's trust store (private CA, or a missing intermediate)`);
  }

  // Node reports one expiry code for the whole chain. If nothing the server sent is out of date, say so
  // instead of letting the leaf's own checks imply it: a trust-store root or this machine's clock may be the cause.
  const outOfDate = (cert: X509Certificate, past: boolean) => (past ? now > new Date(cert.validTo) : now < new Date(cert.validFrom));
  if (options.trustError === 'CERT_HAS_EXPIRED' && !chain.some((c) => outOfDate(c, true))) {
    add('chain.validity_unexplained', 'high', "The handshake reports an expired certificate, but none the server sent is expired. A root in the local trust store may be the cause, or this machine's clock is wrong");
  }
  if (options.trustError === 'CERT_NOT_YET_VALID' && !chain.some((c) => outOfDate(c, false))) {
    add('chain.validity_unexplained', 'high', "The handshake reports a not-yet-valid certificate, but none the server sent is. A root in the local trust store may be the cause, or this machine's clock is wrong");
  }

  return { complete, certificates, findings };
}