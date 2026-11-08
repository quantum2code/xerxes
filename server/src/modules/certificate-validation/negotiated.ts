import type { CertificateFinding, Severity } from './evaluate.js';

export interface NegotiatedTls {
  /** For example TLSv1.3. */
  protocol?: string;
  /** IANA name (TLS_AES_256_GCM_SHA384) or the OpenSSL name when no IANA name is known. */
  cipher?: string;
}

/**
 * Judges the one protocol and cipher suite the server picked for this probe. It cannot say what else the server
 * would accept: that needs one connection per protocol or cipher, which is deliberately not done here.
 */
export function evaluateNegotiated({ protocol, cipher }: NegotiatedTls): CertificateFinding[] {
  const findings: CertificateFinding[] = [];
  const add = (id: string, severity: Severity, message: string) => findings.push({ id, severity, message, category: 'crypto' });

  if (protocol === 'SSLv3') {
    add('tls.legacy_protocol', 'high', 'The server negotiated SSLv3, which is broken (POODLE) and prohibited by RFC 7568');
  } else if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
    add('tls.legacy_protocol', 'medium', `The server negotiated ${protocol}, which RFC 8996 deprecated and current browsers refuse`);
  }

  if (cipher) {
    const name = cipher.toUpperCase().replaceAll('-', '_');
    if (/(^|_)(NULL|EXPORT|EXP|ANON|ADH|AECDH)(_|$)/.test(name)) {
      add('tls.weak_cipher', 'high', `The negotiated cipher suite ${cipher} has no encryption, no authentication or export-grade strength`);
    } else if (/(^|_)(RC4|RC2)(_|$)/.test(name)) {
      add('tls.weak_cipher', 'high', `The negotiated cipher suite ${cipher} uses a broken stream cipher`);
    } else if (/3DES|DES_CBC3/.test(name)) {
      add('tls.weak_cipher', 'medium', `The negotiated cipher suite ${cipher} uses 3DES, which is vulnerable to Sweet32`);
    } else if (/(^|_)DES(_|$)/.test(name)) {
      add('tls.weak_cipher', 'high', `The negotiated cipher suite ${cipher} uses single DES`);
    }
    if (name.startsWith('TLS_RSA_WITH_') && protocol !== 'TLSv1.3') {
      add('tls.no_forward_secrecy', 'low', `The negotiated cipher suite ${cipher} has no forward secrecy: a stolen server key exposes past traffic`);
    }
  }
  return findings;
}