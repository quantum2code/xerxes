import type { X509Certificate } from 'node:crypto';

export interface SignatureInfo {
  oid: string;
  /** Algorithm name when known, otherwise the dotted OID. */
  name: string;
  hash: string | undefined;
  /** MD2, MD4, MD5 or SHA-1: collision attacks make certificates signed this way forgeable. */
  weak: boolean;
}

const KNOWN: Record<string, { name: string; hash?: string }> = {
  '1.2.840.113549.1.1.2': { name: 'md2WithRSAEncryption', hash: 'md2' },
  '1.2.840.113549.1.1.3': { name: 'md4WithRSAEncryption', hash: 'md4' },
  '1.2.840.113549.1.1.4': { name: 'md5WithRSAEncryption', hash: 'md5' },
  '1.2.840.113549.1.1.5': { name: 'sha1WithRSAEncryption', hash: 'sha1' },
  '1.3.14.3.2.29': { name: 'sha1WithRSASignature', hash: 'sha1' },
  '1.2.840.113549.1.1.14': { name: 'sha224WithRSAEncryption', hash: 'sha224' },
  '1.2.840.113549.1.1.11': { name: 'sha256WithRSAEncryption', hash: 'sha256' },
  '1.2.840.113549.1.1.12': { name: 'sha384WithRSAEncryption', hash: 'sha384' },
  '1.2.840.113549.1.1.13': { name: 'sha512WithRSAEncryption', hash: 'sha512' },
  '1.2.840.113549.1.1.10': { name: 'rsassaPss' },
  '1.2.840.10045.4.1': { name: 'ecdsa-with-SHA1', hash: 'sha1' },
  '1.2.840.10045.4.3.1': { name: 'ecdsa-with-SHA224', hash: 'sha224' },
  '1.2.840.10045.4.3.2': { name: 'ecdsa-with-SHA256', hash: 'sha256' },
  '1.2.840.10045.4.3.3': { name: 'ecdsa-with-SHA384', hash: 'sha384' },
  '1.2.840.10045.4.3.4': { name: 'ecdsa-with-SHA512', hash: 'sha512' },
  '1.2.840.10040.4.3': { name: 'dsa-with-sha1', hash: 'sha1' },
  '1.3.101.112': { name: 'Ed25519' },
  '1.3.101.113': { name: 'Ed448' },
};
const WEAK_HASHES = new Set(['md2', 'md4', 'md5', 'sha1']);

/** Minimal DER reader: tag, value start and value end at `offset`. Undefined when the bytes do not fit. */
function readTlv(buf: Buffer, offset: number): { tag: number; start: number; end: number } | undefined {
  if (offset + 2 > buf.length) return undefined;
  const tag = buf[offset]!;
  let length = buf[offset + 1]!;
  let start = offset + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4 || start + count > buf.length) return undefined;
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + buf[start + i]!;
    start += count;
  }
  const end = start + length;
  return end <= buf.length ? { tag, start, end } : undefined;
}

function decodeOid(bytes: Buffer): string | undefined {
  if (!bytes.length || (bytes[bytes.length - 1]! & 0x80)) return undefined;
  const arcs: number[] = [];
  let value = 0;
  for (const byte of bytes) {
    value = value * 128 + (byte & 0x7f);
    if (!(byte & 0x80)) { arcs.push(value); value = 0; }
  }
  const first = arcs.shift()!;
  const head = first < 80 ? [Math.floor(first / 40), first % 40] : [2, first - 80];
  return [...head, ...arcs].join('.');
}

/** Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }. Returns the outer algorithm OID. */
export function signatureOid(cert: X509Certificate): string | undefined {
  try {
    const raw = cert.raw;
    const outer = readTlv(raw, 0);
    if (!outer || outer.tag !== 0x30) return undefined;
    const tbs = readTlv(raw, outer.start);
    if (!tbs || tbs.tag !== 0x30) return undefined;
    const algorithm = readTlv(raw, tbs.end);
    if (!algorithm || algorithm.tag !== 0x30) return undefined;
    const oid = readTlv(raw, algorithm.start);
    if (!oid || oid.tag !== 0x06) return undefined;
    return decodeOid(raw.subarray(oid.start, oid.end));
  } catch {
    return undefined;
  }
}

export function signatureInfo(cert: X509Certificate): SignatureInfo | undefined {
  const oid = signatureOid(cert);
  if (!oid) return undefined;
  const known = KNOWN[oid];
  return { oid, name: known?.name ?? oid, hash: known?.hash, weak: known?.hash !== undefined && WEAK_HASHES.has(known.hash) };
}