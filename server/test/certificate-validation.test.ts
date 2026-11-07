import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import test from 'node:test';
import { evaluateCertificate } from '../src/modules/certificate-validation/evaluate.js';
import { EC_CERT, GOOD_CERT, LONG_CERT, WEAK_CERT } from './fixtures/certificates.js';

const DAY_MS = 86_400_000;
const good = new X509Certificate(GOOD_CERT);
const longCert = new X509Certificate(LONG_CERT);
const weak = new X509Certificate(WEAK_CERT);
const ec = new X509Certificate(EC_CERT);

const daysAfterStart = (cert: X509Certificate, days: number) => new Date(new Date(cert.validFrom).getTime() + days * DAY_MS);
const ids = (report: ReturnType<typeof evaluateCertificate>) => report.findings.map((f) => f.id);

test('a healthy certificate has no findings and is valid', () => {
  const report = evaluateCertificate(good, { hostname: 'example.com', now: daysAfterStart(good, 10) });
  assert.deepEqual(report.findings, []);
  assert.equal(report.valid, true);
  assert.equal(report.details.keyType, 'rsa');
  assert.equal(report.details.keyBits, 2048);
  assert.equal(report.details.selfSigned, false);
  assert.equal(report.details.daysUntilExpiry, 80);
  assert.deepEqual(report.details.subjectAltNames, ['DNS:example.com', 'DNS:www.example.com']);
  assert.match(report.details.issuer, /Test CA/);
  assert.match(report.details.fingerprint256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
});

test('hostname is matched against the SAN list', () => {
  const now = daysAfterStart(good, 10);
  assert.deepEqual(ids(evaluateCertificate(good, { hostname: 'www.example.com', now })), []);

  const wrong = evaluateCertificate(good, { hostname: 'evil.example.org', now });
  assert.deepEqual(ids(wrong), ['cert.hostname_mismatch']);
  assert.equal(wrong.valid, false);

  assert.deepEqual(ids(evaluateCertificate(good, { hostname: '93.184.216.34', now })), ['cert.hostname_mismatch']);
  assert.deepEqual(ids(evaluateCertificate(good, { now })), [], 'no hostname given means no hostname check');
});

test('expired certificates fail', () => {
  const report = evaluateCertificate(good, { hostname: 'example.com', now: daysAfterStart(good, 100) });
  assert.deepEqual(ids(report), ['cert.expired']);
  assert.equal(report.valid, false);
  assert.ok(report.details.daysUntilExpiry < 0);
});

test('certificates that are not valid yet fail', () => {
  const report = evaluateCertificate(good, { hostname: 'example.com', now: daysAfterStart(good, -1) });
  assert.deepEqual(ids(report), ['cert.not_yet_valid']);
  assert.equal(report.valid, false);
});

test('a certificate close to expiry is a low finding and stays valid', () => {
  const report = evaluateCertificate(good, { hostname: 'example.com', now: daysAfterStart(good, 85) });
  assert.deepEqual(report.findings.map((f) => [f.id, f.severity]), [['cert.expiring_soon', 'low']]);
  assert.equal(report.valid, true);
});

test('a weak, self-signed certificate without SAN is flagged on every count', () => {
  const report = evaluateCertificate(weak, { hostname: 'weak.example', now: daysAfterStart(weak, 10) });
  assert.deepEqual(new Set(ids(report)), new Set(['cert.self_signed', 'cert.weak_key', 'cert.no_san']));
  assert.equal(report.valid, false);
  assert.equal(report.details.keyBits, 1024);
  assert.equal(report.details.selfSigned, true);
});

test('EC keys report their curve size and P-256 is not weak', () => {
  const report = evaluateCertificate(ec, { now: daysAfterStart(ec, 10) });
  assert.equal(report.details.keyType, 'ec');
  assert.equal(report.details.keyBits, 256);
  assert.ok(!ids(report).includes('cert.weak_key'));
  assert.ok(ids(report).includes('cert.self_signed'));
});

test('validity longer than 398 days is a low finding', () => {
  const report = evaluateCertificate(longCert, { hostname: 'example.com', now: daysAfterStart(longCert, 10) });
  assert.deepEqual(report.findings.map((f) => [f.id, f.severity]), [['cert.long_validity', 'low']]);
  assert.equal(report.valid, true);
});

test('handshake trust errors add a finding only when nothing else already explains them', () => {
  const now = daysAfterStart(good, 10);
  const untrusted = evaluateCertificate(good, { hostname: 'example.com', now, trustError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' });
  assert.deepEqual(ids(untrusted), ['cert.untrusted_chain']);
  assert.equal(untrusted.valid, false);

  for (const covered of ['CERT_HAS_EXPIRED', 'ERR_TLS_CERT_ALTNAME_INVALID', 'DEPTH_ZERO_SELF_SIGNED_CERT']) {
    assert.ok(!ids(evaluateCertificate(good, { now, trustError: covered })).includes('cert.untrusted_chain'), covered);
  }
});

test('the result is deterministic for the same input', () => {
  const options = { hostname: 'example.com', now: daysAfterStart(good, 10) };
  assert.deepEqual(evaluateCertificate(good, options), evaluateCertificate(good, options));
});
