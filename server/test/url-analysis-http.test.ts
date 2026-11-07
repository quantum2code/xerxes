import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { MockAgent, request } from 'undici';
import { HttpAnalyzer } from '../src/modules/url-analysis/http/client.js';
import { createHttpTransport, type HttpTransport, type HttpSnapshot } from '../src/modules/url-analysis/http/transport.js';
import { DnsAnalyzer } from '../src/modules/url-analysis/dns/resolver.js';
import { loadUrlAnalysisConfig } from '../src/modules/url-analysis/config.js';
import { PolicyError } from '../src/shared/network/policy.js';

const config = loadUrlAnalysisConfig({});
const target = new URL('https://example.com/');
const response = (statusCode = 200, headers: HttpSnapshot['headers'] = {}): HttpSnapshot => ({ statusCode, headers: { 'content-type': 'text/html', ...headers } });
test('HTTP 200 metadata excludes cookies, authorization, server versions and MIME parameters', async () => {
  const result = await new HttpAnalyzer(config, async () => response(200, { 'content-type': 'text/html; charset=utf-8; token=secret', 'content-length': '10', 'set-cookie': 'secret=yes', authorization: 'Bearer token', server: 'secret' })).analyze(target, new AbortController().signal);
  assert.equal(result.status, 'completed'); assert.equal(result.method, 'HEAD'); assert.equal(result.contentLength, 10);
  assert.deepEqual(result.headers, { 'content-type': 'text/html', 'content-length': '10' });
  assert.ok(!JSON.stringify(result).includes('secret'));
});
for (const status of [301, 302, 303, 307, 308]) test(`HTTP ${status} redirects are manual and record cross-domain changes without a verdict`, async () => {
  const calls: string[] = [];
  const transport: HttpTransport = async (url) => { calls.push(url.href); return url.hostname === 'example.com' ? response(status, { location: 'https://www.other.co.uk/final?token=secret' }) : response(); };
  const result = await new HttpAnalyzer(config, transport).analyze(target, new AbortController().signal);
  assert.equal(result.status, 'completed'); assert.equal(calls.length, 2); assert.equal(result.redirects[0]?.crossesRegistrableDomain, true);
  assert.equal(result.redirects[0]?.followed, true); assert.ok(!JSON.stringify(result).includes('secret'));
});
test('redirect loops, missing targets and redirect limits retain observed metadata', async () => {
  const looping = await new HttpAnalyzer(config, async () => response(302, { location: '/' })).analyze(target, new AbortController().signal);
  assert.equal(looping.errors[0]?.code, 'REDIRECT_LOOP'); assert.equal(looping.statusCode, 302);
  const missing = await new HttpAnalyzer(config, async () => response(302)).analyze(target, new AbortController().signal);
  assert.equal(missing.errors[0]?.code, 'INVALID_REDIRECT');
  const limited = await new HttpAnalyzer({ ...config, maxRedirects: 1 }, async (url) => response(302, { location: url.pathname + 'next' })).analyze(target, new AbortController().signal);
  assert.equal(limited.requestCount, 2); assert.equal(limited.errors[0]?.code, 'REDIRECT_LIMIT'); assert.equal(limited.redirects.at(-1)?.followed, false);
});
test('unsafe redirects never reach transport, and DNS-blocked hops are not marked followed', async () => {
  for (const location of ['http://127.0.0.1/', 'http://169.254.169.254/', 'http://[::ffff:127.0.0.1]/', 'http://0x7f000001/', 'https://a.local/']) {
    let calls = 0;
    const result = await new HttpAnalyzer(config, async () => { calls++; return response(302, { location }); }).analyze(target, new AbortController().signal);
    assert.equal(result.status, 'blocked'); assert.equal(calls, 1); assert.equal(result.redirects[0]?.followed, false);
  }
  const dnsBlocked = await new HttpAnalyzer(config, async (url) => { if (url.pathname === '/') return response(302, { location: '/next' }); throw new PolicyError('rebind'); }).analyze(target, new AbortController().signal);
  assert.equal(dnsBlocked.status, 'blocked'); assert.equal(dnsBlocked.redirects[0]?.followed, false);
});
test('HEAD uses one bounded GET fallback only when unsupported or metadata is insufficient', async () => {
  for (const initial of [response(405), response(501), { statusCode: 200, headers: {} }]) {
    const methods: string[] = [];
    const result = await new HttpAnalyzer(config, async (_url, method) => { methods.push(method); return method === 'HEAD' ? initial : response(); }).analyze(target, new AbortController().signal);
    assert.equal(result.status, 'completed'); assert.deepEqual(methods, ['HEAD', 'GET']);
  }
});
test('oversized GET, bad responses, timeouts and TLS errors have structured non-phishing errors', async () => {
  const large = await new HttpAnalyzer(config, async (_url, method) => method === 'HEAD' ? response(405) : response(200, { 'content-length': '9999999' })).analyze(target, new AbortController().signal);
  assert.equal(large.errors[0]?.code, 'RESPONSE_SIZE_LIMIT'); assert.equal(large.statusCode, 405);
  const bad = await new HttpAnalyzer(config, async () => response(0)).analyze(target, new AbortController().signal);
  assert.equal(bad.errors[0]?.code, 'INVALID_HTTP_RESPONSE');
  const timeout = await new HttpAnalyzer({ ...config, requestTimeoutMs: 10 }, async (_url, _method, signal) => { await delay(100, undefined, { signal }); return response(); }).analyze(target, new AbortController().signal);
  assert.equal(timeout.status, 'timed_out');
  const tls = await new HttpAnalyzer(config, async () => { throw Object.assign(new Error('secret certificate contents'), { code: 'CERT_HAS_EXPIRED' }); }).analyze(target, new AbortController().signal);
  assert.equal(tls.errors[0]?.code, 'CERT_HAS_EXPIRED'); assert.ok(!JSON.stringify(tls).includes('secret'));
});
test('real Undici MockAgent exercises metadata response handling without global dispatchers or external network', async (t) => {
  const mock = new MockAgent(); mock.disableNetConnect(); t.after(() => mock.close());
  mock.get(target.origin).intercept({ path: '/', method: 'HEAD' }).reply(405, '');
  mock.get(target.origin).intercept({ path: '/', method: 'GET' }).reply(200, 'bounded fixture', { headers: { 'content-type': 'text/plain', 'content-length': '15' } });
  const dns = new DnsAnalyzer(config, async (type) => type === 'A' ? [{ address: '8.8.8.8', ttl: 30 }] : []);
  const dispatchers: unknown[] = [];
  const transport = createHttpTransport(config, dns, (url, options) => { dispatchers.push(options?.dispatcher); return request(url, { ...options, dispatcher: mock }); });
  const result = await new HttpAnalyzer(config, transport).analyze(target, new AbortController().signal);
  assert.equal(result.status, 'completed'); assert.equal(result.method, 'GET'); assert.equal(result.contentType, 'text/plain');
  assert.notStrictEqual(dispatchers[0], dispatchers[1]); mock.assertNoPendingInterceptors();
});
test('transport validates every DNS address and fresh answers for every request, before dispatch', async () => {
  let phase = 0; let sends = 0;
  const dns = new DnsAnalyzer(config, async (type) => type === 'A' ? [{ address: phase ? '127.0.0.1' : '8.8.8.8', ttl: 30 }] : []);
  const mock = new MockAgent(); mock.disableNetConnect(); mock.get(target.origin).intercept({ method: 'HEAD', path: '/' }).reply(200, '', { headers: { 'content-type': 'text/html' } });
  try {
    const transport = createHttpTransport(config, dns, (url, options) => { sends++; return request(url, { ...options, dispatcher: mock }); });
    await transport(target, 'HEAD', new AbortController().signal); phase = 1;
    await assert.rejects(transport(target, 'HEAD', new AbortController().signal), /prohibited/);
    assert.equal(sends, 1);
  } finally { await mock.close(); }
});
