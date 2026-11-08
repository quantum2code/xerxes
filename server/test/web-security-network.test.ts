import assert from 'node:assert/strict';
import test from 'node:test';
import { loadConfig } from '../src/modules/web-security/config.js';
import { authorize, parseTarget, publicAddress, resolvePublic } from '../src/modules/web-security/network/policy.js';
import { createTransport } from '../src/modules/web-security/network/transport.js';
import { normalize, redact, safeUrl } from '../src/modules/web-security/reporting/normalize.js';

test('strict URLs reject malformed schemes, credentials, ports and local names', () => {
  for (const url of ['garbage', 'file:///etc/passwd', 'ftp://example.com', 'https://user:pass@example.com', 'http://example.com:8080', 'http://localhost', 'http://a.local', 'http://example.com\\@localhost', 'http://example.com/#x']) {
    assert.throws(() => parseTarget(url));
  }
  assert.equal(parseTarget('https://example.com/path').origin, 'https://example.com');
});
test('nonpublic IPv4/IPv6, mapped and metadata addresses are blocked', () => {
  for (const ip of ['127.0.0.1', '0.0.0.0', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '168.63.129.16', '100.100.100.200', '224.0.0.1', '192.0.2.1', '::1', '::', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1', '64:ff9b::7f00:1']) assert.equal(publicAddress(ip), false, ip);
  assert.equal(publicAddress('93.184.216.34'), true);
  assert.equal(publicAddress('2606:4700:4700::1111'), true);
});
test('all DNS answers are validated and numeric host aliases are normalized', async () => {
  await assert.rejects(resolvePublic(parseTarget('http://2130706433')));
  await assert.rejects(resolvePublic(parseTarget('https://example.com'), async () => [{ address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 }]));
});
test('DNS timeout cannot initiate a late connection', async () => {
  const transport = createTransport({ ...loadConfig({}), requestTimeoutMs: 10 }, () => new Promise(() => {}));
  await assert.rejects(transport(new URL('https://example.com'), new AbortController().signal), /deadline/);
});
test('authorization binds server-side grants to exact origin, mode and expiry', () => {
  const token = 'x'.repeat(32);
  const config = loadConfig({ WEB_SECURITY_GRANTS: JSON.stringify([{ token, origin: 'https://example.com', modes: ['active'], expiresAt: '2099-01-01' }]) });
  assert.doesNotThrow(() => authorize({ url: '', mode: 'active', authorizationToken: token }, new URL('https://example.com'), config));
  for (const origin of ['https://other.example', 'http://example.com']) assert.throws(() => authorize({ url: '', mode: 'active', authorizationToken: token }, new URL(origin), config));
  assert.throws(() => authorize({ url: '', mode: 'active' }, new URL('https://example.com'), config));
  assert.throws(() => authorize({ url: '', mode: 'passive', authorizationToken: token }, new URL('https://example.com'), config));
});
test('normalization validates classifications and redacts secrets', () => {
  assert.equal(redact('password=hunter2'), 'password=[REDACTED]');
  assert.ok(!safeUrl('https://u:p@example.com/?access=secret').includes('secret'));
  const finding = { checkId: 'test', title: 'test', description: 'test', severity: 'low' as const, confidence: 'high' as const, affectedUrl: 'https://example.com/?q=secret', evidence: [{ location: 'header', observation: 'Bearer abc123' }], remediation: 'fix' };
  const normalized = normalize(finding);
  assert.ok(!JSON.stringify(normalized).includes('abc123'));
  assert.ok(!JSON.stringify(normalized).includes('secret'));
  assert.notEqual(normalize(finding).id, normalized.id);
  assert.throws(() => normalize({ ...finding, severity: 'bogus' as 'low' }));
  assert.throws(() => normalize({ ...finding, confidence: 'bogus' as 'low' }));
  assert.throws(() => normalize({ ...finding, evidence: [{ location: 'response', observation: '' }] }));
  assert.throws(() => normalize({ ...finding, source: 'bogus' as 'native' }));
});
test('invalid environment configuration fails without exposing secret-bearing JSON', () => {
  assert.throws(() => loadConfig({ WEB_SECURITY_MAX_REQUESTS: '-1' }), /Invalid WEB_SECURITY_MAX_REQUESTS/);
  assert.throws(() => loadConfig({ WEB_SECURITY_GRANTS: '{"token":"topsecret",bad}' }), (error: unknown) => error instanceof Error && !error.message.includes('topsecret'));
  assert.throws(() => loadConfig({ WEB_SECURITY_GRANTS: JSON.stringify([{ token: 'x'.repeat(32), origin: 'invalid-secret-origin', modes: ['passive'], expiresAt: '2099-01-01' }]) }), (error: unknown) => error instanceof Error && !error.message.includes('invalid-secret-origin'));
});
