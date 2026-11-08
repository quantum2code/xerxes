import assert from 'node:assert/strict';
import test from 'node:test';
import { defaultChecks } from '../src/modules/web-security/checks/index.js';
import { normalize } from '../src/modules/web-security/reporting/normalize.js';
import type { Page } from '../src/modules/web-security/types.js';

const page = (body = '', headers: Page['headers'] = {}): Page => ({ url: 'https://example.com/', status: 200, headers: { 'content-type': 'text/html', ...headers }, body });
const run = (id: string, p: Page) => defaultChecks.find((c) => c.id === id)!.run(p);

test('header observations are low severity, context-aware, and recognize enforcing protections', () => {
  const findings = run('security-headers', page());
  assert.equal(findings.length, 5);
  assert.ok(findings.every((f) => f.severity === 'low'));
  assert.equal(run('security-headers', page('', {
    'content-security-policy': "default-src 'self'; frame-ancestors 'none'", 'strict-transport-security': 'max-age=31536000',
    'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin',
  })).length, 0);
  assert.ok(run('security-headers', page('', { 'content-security-policy-report-only': "default-src 'none'" })).some((f) => f.title.includes('not observed')));
  assert.equal(run('security-headers', page('', { 'content-security-policy': "script-src 'self' 'unsafe-inline'", 'x-frame-options': 'ALLOW-FROM https://example.com' })).filter((f) => /script policy|Framing/.test(f.title)).length, 2);
});
test('cookies handle separate Set-Cookie values and omit all cookie material', () => {
  const findings = run('cookies', page('', { 'set-cookie': ['session=supersecret; SameSite=None', 'safe=x; Secure; HttpOnly; SameSite=Lax'] }));
  assert.equal(findings.length, 2);
  assert.ok(!JSON.stringify(findings).includes('supersecret'));
  assert.equal(run('cookies', page()).length, 0);
});
test('CORS does not call wildcard credential combination exploitable', () => {
  assert.equal(run('cors', page('', { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' }))[0]?.severity, 'low');
  assert.equal(run('cors', page('', { 'access-control-allow-origin': '*' }))[0]?.severity, 'informational');
  assert.equal(run('cors', page('', { 'access-control-allow-origin': 'null', 'access-control-allow-credentials': 'true' }))[0]?.confidence, 'medium');
  assert.equal(run('cors', page('', { 'access-control-allow-origin': 'https://trusted.example' })).length, 0);
});
test('mixed content handles base URLs and distinguishes anchors from resources', () => {
  const findings = run('mixed-content', page('<base href="http://example.com/"><script src="a.js"></script><a href="http://other.example">ok</a><img srcset="x.png 1x, y.png 2x">'));
  assert.equal(findings.length, 3);
  assert.equal(run('mixed-content', { ...page('<script src="http://example.com/a"></script>'), url: 'http://example.com' }).length, 0);
});
test('information disclosures have structural evidence rather than leaked data', () => {
  const findings = run('information-disclosure', page('<!-- TODO secret=hunter2 -->Traceback (most recent call last):', { server: 'nginx/1.0' }));
  assert.equal(findings.length, 3);
  assert.ok(!JSON.stringify(findings).includes('hunter2'));
  assert.equal(run('information-disclosure', page('ordinary content')).length, 0);
});
test('directory listing needs multiple indicators', () => {
  assert.equal(run('directory-listing', page('<h1>Index of /</h1>')).length, 0);
  assert.equal(run('directory-listing', page('<h1>Index of /</h1><a href="../">Parent Directory</a>')).length, 1);
});
test('sensitive exposure reports markers without echoing secrets or testing credentials', () => {
  const findings = run('sensitive-exposure', page('-----BEGIN RSA PRIVATE KEY-----\nsecret\nDB_PASSWORD=hunter2'));
  assert.equal(findings.length, 2);
  assert.ok(findings.every((f) => f.confidence === 'medium'));
  assert.ok(!JSON.stringify(findings).includes('hunter2'));
});
test('forms resolve actions correctly and never submit data', () => {
  assert.equal(run('insecure-forms', page('<form action="http://example.com/login"></form>')).length, 1);
  assert.equal(run('insecure-forms', page('<form action="/login"></form><form></form>')).length, 0);
  assert.equal(run('insecure-forms', page('<form id="login"><input type="password" name="pw" value="secret"></form>')).length, 1);
  assert.equal(run('insecure-forms', page('<form id="login" method="post"></form><input form="login" type="password" name="pw">')).length, 0);
  assert.equal(run('insecure-forms', page('<form method="post"><button formaction="http://example.com/">Submit</button></form>')).length, 1);
});
test('dependency findings require fetched content banners and a real advisory range', () => {
  assert.equal(run('dependencies', page('<script src="jquery-1.2.3.js"></script>')).length, 0);
  assert.equal(run('dependencies', page('/*! jQuery v3.4.1 | license */', { 'content-type': 'application/javascript' }))[0]?.cves?.[0], 'CVE-2020-11022');
  assert.equal(run('dependencies', page('/*! jQuery v3.5.0 */', { 'content-type': 'application/javascript' })).length, 0);
});
test('all checks accept empty/malformed HTML and every emitted finding normalizes', () => {
  for (const check of defaultChecks) for (const p of [page(), page('<form><script><div><input action=":::">'), page('x', { 'content-type': 'application/octet-stream' })]) {
    for (const finding of check.run(p)) assert.doesNotThrow(() => normalize(finding));
  }
});
test('oversized/malicious HTML structure remains bounded and does not inspect beyond coverage', () => {
  assert.equal(run('insecure-forms', page(' '.repeat(262_144) + '<form action="http://example.com/"></form>')).length, 0);
  assert.equal(run('insecure-forms', page('<i></i>'.repeat(10_001) + '<form action="http://example.com/"></form>')).length, 0);
  assert.equal(run('sensitive-exposure', page('\n'.repeat(100_000))).length, 0);
});
