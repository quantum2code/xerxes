import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { loadConfig } from '../src/modules/web-security/config.js';
import { WebSecurityScanner } from '../src/modules/web-security/scanner.js';
import { PolicyError } from '../src/modules/web-security/network/policy.js';
import type { Page } from '../src/modules/web-security/types.js';

const token = 'test-authorization-'.repeat(3);
const config = { ...loadConfig({}), requestIntervalMs: 1, grants: [{ token, origin: 'https://example.com', modes: ['passive' as const, 'active' as const], expiresAt: '2099-01-01' }] };
const request = { url: 'https://example.com/', authorizationToken: token };
const page = (url: URL, body = '', headers: Page['headers'] = {}): Page => ({ url: url.href, body, headers: { 'content-type': 'text/html', ...headers }, status: 200 });

test('scanner runs all checks with consistent counts and secret-free evidence', async () => {
  const scanner = new WebSecurityScanner(config, { transport: async (url) => page(url, '<form action="http://example.com/login?token=private"></form>') });
  const result = await scanner.scan(request);
  assert.equal(result.status, 'completed');
  assert.equal(result.checksExecuted.length, 9);
  assert.equal(Object.values(result.counts).reduce((a, b) => a + b, 0), result.findings.length);
  assert.ok(!JSON.stringify(result).includes('private'));
  assert.equal(result.backend.zap, 'disabled');
});
test('bad input, unauthorized passive and active requests never invoke transport', async () => {
  let calls = 0;
  const scanner = new WebSecurityScanner(config, { transport: async (url) => { calls++; return page(url); } });
  for (const input of [null, {}, { url: 'file:///etc/passwd' }, { url: request.url }, { url: request.url, mode: 'active', authorized: true }, { ...request, mode: 'bogus' }]) assert.equal((await scanner.scan(input)).status, 'blocked');
  assert.equal(calls, 0);
});
test('redirects are explicit, same-origin only, and loop/count bounded', async () => {
  for (const location of ['http://127.0.0.1', 'https://other.example/', 'https://example.com/']) {
    let calls = 0;
    const scanner = new WebSecurityScanner(config, { transport: async (url) => { calls++; return { ...page(url), status: 302, headers: { location } }; } });
    assert.equal((await scanner.scan(request)).status, 'partial');
    assert.equal(calls, 1);
  }
});
test('safe crawling is bounded and ignores off-origin links, queries and destructive paths', async () => {
  const calls: string[] = [];
  const scanner = new WebSecurityScanner({ ...config, maxRequests: 2 }, { transport: async (url) => {
    calls.push(url.href);
    return page(url, '<a href="/a">a</a><a href="/b">b</a><a href="/logout">x</a><a href="https://other.example">x</a><a href="/?delete=1">x</a>');
  } });
  const result = await scanner.scan(request);
  assert.equal(calls.length, 2);
  assert.equal(result.status, 'partial');
});
test('network policy failures are blocked; timeouts and malformed responses fail, never safe', async () => {
  const blocked = new WebSecurityScanner(config, { transport: async () => { throw new PolicyError('internal'); } });
  assert.equal((await blocked.scan(request)).status, 'blocked');
  const failed = new WebSecurityScanner(config, { transport: async () => { throw new Error('secret internal failure'); } });
  const result = await failed.scan(request);
  assert.equal(result.status, 'failed'); assert.ok(!JSON.stringify(result).includes('secret internal'));
  const malformed = new WebSecurityScanner(config, { transport: async (url) => ({ ...page(url), status: 0 }) });
  assert.equal((await malformed.scan(request)).status, 'failed');
});
test('partial failures retain successful findings and report skipped checks', async () => {
  const scanner = new WebSecurityScanner(config, { transport: async (url) => page(url), checks: [
    { id: 'broken', run() { throw new Error(); } },
    { id: 'valid', run(p) { return [{ checkId: 'valid', title: 't', description: 'd', severity: 'high', confidence: 'low', affectedUrl: p.url, evidence: [{ location: 'test', observation: 'test' }], remediation: 'fix' }]; } },
  ] });
  const result = await scanner.scan(request);
  assert.equal(result.status, 'partial'); assert.equal(result.counts.high, 1);
  assert.ok(result.checksSkipped.some((c) => c.checkId === 'broken'));
});
test('concurrent scans have isolated results and reject excess capacity', async () => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const scanner = new WebSecurityScanner({ ...config, maxConcurrentScans: 1 }, { transport: async (url) => { await gate; return page(url); } });
  const first = scanner.scan(request);
  const second = await scanner.scan(request);
  assert.equal(second.status, 'blocked'); release();
  const completed = await first;
  const next = await scanner.scan(request);
  assert.equal(completed.status, 'completed'); assert.equal(next.status, 'completed');
  assert.notStrictEqual(completed.findings, next.findings);
});
test('ZAP unavailable/errors are explicit and active scans cannot silently become complete passive scans', async () => {
  const cfg = { ...config, zap: { ...config.zap, enabled: true } };
  const scanner = new WebSecurityScanner(cfg, { transport: async (url) => page(url), zap: async () => ({ status: 'unavailable', findings: [], limitations: ['Docker not available'] }) });
  const result = await scanner.scan({ ...request, mode: 'active' });
  assert.equal(result.status, 'partial'); assert.equal(result.backend.zap, 'unavailable');
  const throws = new WebSecurityScanner(cfg, { transport: async (url) => page(url), zap: async () => { throw new Error(); } });
  assert.equal((await throws.scan(request)).backend.zap, 'failed');
});
test('scan deadlines cancel in-flight work and authorization expiry bounds the scan', async () => {
  for (const cfg of [
    { ...config, scanTimeoutMs: 10 },
    { ...config, grants: [{ ...config.grants[0]!, expiresAt: new Date(Date.now() + 30).toISOString() }] },
  ]) {
    const scanner = new WebSecurityScanner(cfg, { transport: async (url, signal) => { await delay(500, undefined, { signal }); return page(url); } });
    const result = await scanner.scan(request);
    assert.ok(['failed', 'blocked'].includes(result.status));
    assert.equal(result.findings.length, 0);
  }
});
test('two allowed concurrent scans retain distinct result/finding objects', async () => {
  const scanner = new WebSecurityScanner(config, { transport: async (url) => { await delay(5); return page(url); } });
  const [a, b] = await Promise.all([scanner.scan(request), scanner.scan(request)]);
  assert.equal(a.status, 'completed'); assert.equal(b.status, 'completed');
  assert.notStrictEqual(a.findings, b.findings); assert.notEqual(a.findings[0]?.id, b.findings[0]?.id);
});
