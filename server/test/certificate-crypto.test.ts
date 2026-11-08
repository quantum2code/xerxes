import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import test from 'node:test';
import { createCertificateTask, evaluateCertificate, evaluateChain, evaluateNegotiated, signatureInfo, type Connector } from '../src/modules/certificate-validation/index.js';
import { CHAIN_INTER, CHAIN_LEAF, CHAIN_ROOT } from './fixtures/certificate-chain.js';
import { EC_CERT } from './fixtures/certificates.js';

const DAY_MS = 86_400_000;
const [leaf, inter, root] = [CHAIN_LEAF, CHAIN_INTER, CHAIN_ROOT].map((pem) => new X509Certificate(pem)) as [X509Certificate, X509Certificate, X509Certificate];
const at = (days: number) => new Date(new Date(leaf.validFrom).getTime() + days * DAY_MS);

const SHA1 = 0x05;
const MD5 = 0x04;
const SHA256_RSA = Buffer.from('06092a864886f70d01010b0500', 'hex');
/** The same certificate with only the outer signature algorithm OID changed (sha256WithRSA to sha1 or md5). */
function resigned(cert: X509Certificate, lastOidByte: number): X509Certificate {
  const der = Buffer.from(cert.raw);
  const position = der.lastIndexOf(SHA256_RSA);
  assert.ok(position > 0, 'fixture is signed with sha256WithRSAEncryption');
  der[position + 10] = lastOidByte;
  return new X509Certificate(der);
}
const run = (peer: Awaited<ReturnType<Connector>>) => createCertificateTask({
  resolver: async () => [{ address: '8.8.8.8', family: 4 }], now: () => at(10), connect: async () => peer,
})({ url: 'https://chain.example' });

test('the signature algorithm is read from the certificate DER', () => {
  assert.deepEqual(signatureInfo(leaf), { oid: '1.2.840.113549.1.1.11', name: 'sha256WithRSAEncryption', hash: 'sha256', weak: false });
  assert.equal(signatureInfo(new X509Certificate(EC_CERT))?.name, 'ecdsa-with-SHA256');
  assert.deepEqual([signatureInfo(resigned(leaf, SHA1))?.name, signatureInfo(resigned(leaf, MD5))?.name], ['sha1WithRSAEncryption', 'md5WithRSAEncryption']);
  assert.equal(signatureInfo({ raw: Buffer.from([1, 2, 3]) } as unknown as X509Certificate), undefined);
});

test('a SHA-1 or MD5 signed leaf is a high crypto finding', () => {
  for (const [byte, name] of [[SHA1, 'sha1WithRSAEncryption'], [MD5, 'md5WithRSAEncryption']] as const) {
    const report = evaluateCertificate(resigned(leaf, byte), { hostname: 'chain.example', now: at(10) });
    assert.deepEqual(report.findings.map((f) => [f.id, f.severity]), [['cert.weak_signature', 'high']]);
    assert.equal(report.details.signatureAlgorithm, name);
    assert.equal(report.valid, false);
  }
  assert.equal(evaluateCertificate(leaf, { hostname: 'chain.example', now: at(10) }).details.signatureAlgorithm, 'sha256WithRSAEncryption');
});

test('a weak signature on an intermediate is reported, but a trust-anchor root is not', () => {
  const report = evaluateChain([leaf, resigned(inter, SHA1)], { now: at(10) });
  assert.deepEqual(report.findings.map((f) => [f.id, f.severity, f.category]), [['chain.weak_signature', 'high', 'crypto']]);
  assert.match(report.findings[0]!.message, /sha1WithRSAEncryption/);
  assert.deepEqual(evaluateChain([leaf, inter, resigned(root, SHA1)], { now: at(10) }).findings, []);
});
test('weak signatures reach the task result as crypto findings and fail validation', async () => {
  const result = await run({ cert: resigned(leaf, MD5), authorized: true });
  assert.equal(result.valid, false);
  assert.deepEqual(result.findings.map((f) => [f.id, f.category]), [['cert.weak_signature', 'crypto']]);
  assert.equal(result.details?.signatureAlgorithm, 'md5WithRSAEncryption');
});

test('negotiated protocol and cipher are judged', () => {
  const summary = (protocol: string, cipher: string) => evaluateNegotiated({ protocol, cipher }).map((f) => [f.id, f.severity]);
  assert.deepEqual(evaluateNegotiated({}), []);
  assert.deepEqual(summary('TLSv1.3', 'TLS_AES_256_GCM_SHA384'), []);
  assert.deepEqual(summary('TLSv1.2', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'), []);
  assert.deepEqual(summary('TLSv1.1', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'), [['tls.legacy_protocol', 'medium']]);
  assert.deepEqual(summary('SSLv3', 'TLS_RSA_WITH_AES_128_CBC_SHA'), [['tls.legacy_protocol', 'high'], ['tls.no_forward_secrecy', 'low']]);
  assert.deepEqual(summary('TLSv1.2', 'TLS_RSA_WITH_RC4_128_SHA'), [['tls.weak_cipher', 'high'], ['tls.no_forward_secrecy', 'low']]);
  assert.deepEqual(summary('TLSv1.2', 'TLS_RSA_WITH_NULL_SHA'), [['tls.weak_cipher', 'high'], ['tls.no_forward_secrecy', 'low']]);
  assert.deepEqual(summary('TLSv1.2', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA'), [['tls.weak_cipher', 'medium']]);
  assert.deepEqual(summary('TLSv1.2', 'TLS_DH_anon_WITH_AES_128_CBC_SHA'), [['tls.weak_cipher', 'high']]);
  assert.deepEqual(summary('TLSv1.2', 'DES-CBC3-SHA'), [['tls.weak_cipher', 'medium']]);
});

test('the task reports the negotiated protocol and cipher and judges them', async () => {
  const modern = await run({ cert: leaf, authorized: true, protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384' });
  assert.deepEqual([modern.valid, modern.findings, modern.tls], [true, [], { protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384' }]);
  const old = await run({ cert: leaf, authorized: true, protocol: 'TLSv1', cipher: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA' });
  assert.deepEqual(old.findings.map((f) => [f.id, f.category]), [['tls.legacy_protocol', 'crypto'], ['tls.weak_cipher', 'crypto'], ['tls.no_forward_secrecy', 'crypto']]);
  assert.equal(old.valid, true, 'medium and low findings do not fail validation');
  assert.equal((await run({ cert: leaf, authorized: true })).tls, undefined);
});