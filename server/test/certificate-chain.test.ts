import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import type tls from 'node:tls';
import test from 'node:test';
import { categorize, chainFromPeer, createCertificateTask, evaluateChain, type Connector } from '../src/modules/certificate-validation/index.js';
import { parseTlsTarget } from '../src/modules/certificate-validation/guard.js';
import { CHAIN_INTER, CHAIN_LEAF, CHAIN_LEAF_NOCA, CHAIN_NOCA, CHAIN_ROOT } from './fixtures/certificate-chain.js';
import { WEAK_CERT } from './fixtures/certificates.js';

const DAY_MS = 86_400_000;
const [leaf, inter, root, noca, leafNoCa, weak] = [CHAIN_LEAF, CHAIN_INTER, CHAIN_ROOT, CHAIN_NOCA, CHAIN_LEAF_NOCA, WEAK_CERT].map((pem) => new X509Certificate(pem)) as [X509Certificate, X509Certificate, X509Certificate, X509Certificate, X509Certificate, X509Certificate];
const at = (days: number) => new Date(new Date(leaf.validFrom).getTime() + days * DAY_MS);
const ids = (findings: { id: string }[]) => findings.map((f) => f.id);

test('chainFromPeer walks issuer links and stops at a self-referencing root', () => {
  const peerOf = (cert: X509Certificate, issuerCertificate?: unknown) => ({ raw: cert.raw, fingerprint256: cert.fingerprint256, issuerCertificate }) as Record<string, unknown>;
  const rootPeer = peerOf(root); rootPeer.issuerCertificate = rootPeer;
  const chain = chainFromPeer(peerOf(leaf, peerOf(inter, rootPeer)) as unknown as tls.DetailedPeerCertificate);
  assert.deepEqual(chain.map((c) => c.fingerprint256), [leaf, inter, root].map((c) => c.fingerprint256));
  const a = peerOf(leaf); const b = peerOf(inter, a); a.issuerCertificate = b;
  assert.equal(chainFromPeer(a as unknown as tls.DetailedPeerCertificate).length, 2, 'a loop between two certificates ends');
  assert.deepEqual(chainFromPeer({} as tls.DetailedPeerCertificate), []);
});

test('a complete, healthy chain has roles, facts and no findings', () => {
  const report = evaluateChain([leaf, inter, root], { now: at(10) });
  assert.deepEqual(report.findings, []);
  assert.equal(report.complete, true);
  assert.deepEqual(report.certificates.map((c) => c.role), ['leaf', 'intermediate', 'root']);
  assert.deepEqual(report.certificates.map((c) => [c.isCa, c.selfSigned]), [[false, false], [true, false], [true, true]]);
  assert.equal(report.certificates[1]?.daysUntilExpiry, 355);
});

test('missing intermediate and unknown issuer are different findings', () => {
  const missing = evaluateChain([leaf], { now: at(10), trustError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' });
  assert.deepEqual(ids(missing.findings), ['chain.incomplete']);
  assert.equal(missing.complete, false);
  const unknown = evaluateChain([leaf, inter], { now: at(10), trustError: 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY' });
  assert.deepEqual(ids(unknown.findings), ['chain.unknown_issuer']);
  assert.match(unknown.findings[0]!.message, /Chain Test Root/);
  assert.equal(unknown.complete, true);
});

test('an issuer that is not a CA, or does not match, is reported', () => {
  assert.deepEqual(ids(evaluateChain([leafNoCa, noca, root], { now: at(10) }).findings), ['chain.not_a_ca']);
  const mismatched = ids(evaluateChain([leaf, noca], { now: at(10) }).findings);
  assert.ok(mismatched.includes('chain.broken_link') && mismatched.includes('chain.not_a_ca'));
});

test('intermediate expiry is dated correctly, warned about early, and not-yet-valid is caught', () => {
  const expired = evaluateChain([leaf, inter, root], { now: at(400) });
  assert.deepEqual(expired.findings.map((f) => [f.id, f.severity]), [['chain.expired', 'high']]);
  assert.match(expired.findings[0]!.message, /expired 35 day\(s\) ago/);
  assert.deepEqual(evaluateChain([leaf, inter, root], { now: at(360) }).findings.map((f) => [f.id, f.severity]), [['chain.expiring_soon', 'low']]);
  assert.deepEqual(ids(evaluateChain([leaf, inter, root], { now: at(-1) }).findings), ['chain.not_yet_valid', 'chain.not_yet_valid']);
});

test('weak keys in the chain are crypto findings', () => {
  const finding = evaluateChain([leaf, weak], { now: at(10) }).findings.find((f) => f.id === 'chain.weak_key');
  assert.equal(finding?.severity, 'high');
  assert.equal(finding?.category, 'crypto');
});

test('an expiry error nobody in the chain explains is called out; an explained one is not', () => {
  const unexplained = evaluateChain([leaf, inter, root], { now: at(10), trustError: 'CERT_HAS_EXPIRED' });
  assert.deepEqual(ids(unexplained.findings), ['chain.validity_unexplained']);
  assert.match(unexplained.findings[0]!.message, /clock/);
  assert.ok(!ids(evaluateChain([leaf, inter, root], { now: at(400), trustError: 'CERT_HAS_EXPIRED' }).findings).includes('chain.validity_unexplained'));
  assert.deepEqual(ids(evaluateChain([leaf, inter, root], { now: at(10), trustError: 'CERT_NOT_YET_VALID' }).findings), ['chain.validity_unexplained']);
});

test('categorize keeps an existing category and maps the leaf findings to the three Engine 3 areas', () => {
  const f = (id: string, category?: 'crypto') => ({ id, severity: 'high' as const, message: 'm', category });
  assert.deepEqual(['cert.expired', 'cert.hostname_mismatch', 'cert.no_san', 'cert.self_signed', 'cert.untrusted_chain', 'cert.weak_key'].map((id) => categorize(f(id)).category),
    ['validity', 'validity', 'validity', 'chain', 'chain', 'crypto']);
  assert.equal(categorize(f('chain.x', 'crypto')).category, 'crypto');
});

test('the task combines leaf and chain findings and reports every certificate', async () => {
  const run = async (peer: Awaited<ReturnType<Connector>>) => createCertificateTask({
    resolver: async () => [{ address: '8.8.8.8', family: 4 }], now: () => at(10), connect: async () => peer,
  })({ url: 'https://chain.example' });
  const clean = await run({ cert: leaf, chain: [leaf, inter, root], authorized: true });
  assert.deepEqual([clean.valid, clean.findings, clean.chain?.complete, clean.chain?.certificates.length], [true, [], true, 3]);
  const odd = await run({ cert: leaf, chain: [leaf, inter, root], authorized: false, authorizationError: 'CERT_HAS_EXPIRED' });
  assert.equal(odd.valid, false);
  assert.deepEqual(odd.findings.map((f) => [f.id, f.category]), [['chain.validity_unexplained', 'chain']]);
  const bare = await run({ cert: leaf, authorized: true });
  assert.equal(bare.chain, undefined);
});

test('TLS targets: https on 443 only, no credentials, no local-looking names', () => {
  for (const ok of ['https://example.com', 'https://example.com:443/path?q=1', 'https://[2606:4700::1111]']) assert.doesNotThrow(() => parseTlsTarget(ok), ok);
  for (const bad of ['http://example.com', 'ftp://example.com', 'https://u:p@example.com', 'https://example.com:8443', 'https://localhost', 'https://a.local', 'https://example.com.', 'https://exa mple.com', 42, null]) {
    assert.throws(() => parseTlsTarget(bad), String(bad));
  }
});

test('modules stay separate: no file imports from outside the module', () => {
  const dir = new URL('../src/modules/certificate-validation/', import.meta.url);
  for (const file of readdirSync(dir).filter((name) => name.endsWith('.ts'))) {
    const outside = /from\s+['"]\.\.\//.test(readFileSync(new URL(file, dir), 'utf8'));
    assert.equal(outside, false, `${file} imports from outside the module`);
  }
});
test('a private root the server sent is reported as an unknown issuer', () => {
  const report = evaluateChain([leaf, inter, root], { now: at(10), trustError: 'SELF_SIGNED_CERT_IN_CHAIN' });
  assert.deepEqual(ids(report.findings), ['chain.unknown_issuer']);
  assert.match(report.findings[0]!.message, /Chain Test Root/);
});

test('the leaf untrusted-chain finding is dropped when a chain finding already explains it', async () => {
  const run = (peer: Awaited<ReturnType<Connector>>) => createCertificateTask({
    resolver: async () => [{ address: '8.8.8.8', family: 4 }], now: () => at(10), connect: async () => peer,
  })({ url: 'https://chain.example' });
  const missing = await run({ cert: leaf, chain: [leaf], authorized: false, authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' });
  assert.deepEqual(missing.findings.map((f) => f.id), ['chain.incomplete']);
  const bare = await run({ cert: leaf, authorized: false, authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' });
  assert.ok(bare.findings.some((f) => f.id === 'cert.untrusted_chain'), 'without chain data the leaf finding stays');
});
test('a missing intermediate or a private root makes the result invalid', async () => {
  const run = (peer: Awaited<ReturnType<Connector>>) => createCertificateTask({
    resolver: async () => [{ address: '8.8.8.8', family: 4 }], now: () => at(10), connect: async () => peer,
  })({ url: 'https://chain.example' });
  const missing = await run({ cert: leaf, chain: [leaf], authorized: false, authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' });
  assert.equal(missing.valid, false);
  assert.deepEqual(missing.findings.map((f) => [f.id, f.severity]), [['chain.incomplete', 'high']]);
  const privateRoot = await run({ cert: leaf, chain: [leaf, inter, root], authorized: false, authorizationError: 'SELF_SIGNED_CERT_IN_CHAIN' });
  assert.equal(privateRoot.valid, false);
  assert.deepEqual(privateRoot.findings.map((f) => f.id), ['chain.unknown_issuer']);
});