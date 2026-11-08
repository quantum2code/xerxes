import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { UrlAnalyzer, loadUrlAnalysisConfig } from '../src/modules/url-analysis/index.js';
import { PolicyError } from '../src/shared/network/policy.js';

const config = loadUrlAnalysisConfig({});
const query = async () => [];
const transport = async () => ({ statusCode: 200, headers: { 'content-type': 'text/html' } });
test('module result is typed, redacted, feature-rich, and does not contain risk scoring', async () => {
  const result = await new UrlAnalyzer(config, { query, transport }).analyze({ url: 'https://www.example.com/login?token=secret#fragment', authorizationToken: 'never-return-this' });
  assert.equal(result.module, 'urlAnalysis'); assert.equal(result.status, 'completed'); assert.equal(result.features?.terms.login, true);
  assert.equal(result.url?.domain, 'example.com'); assert.equal(result.url?.hasFragment, true);
  assert.ok(!JSON.stringify(result).includes('never-return-this')); assert.ok(!JSON.stringify(result).includes('=secret'));
  assert.ok(!('score' in result) && !('verdict' in result));
});
test('unsafe literal/local targets are blocked before DNS and HTTP, while parsing/features remain', async () => {
  let queries = 0; let requests = 0;
  const analyzer = new UrlAnalyzer(config, { query: async () => { queries++; return []; }, transport: async () => { requests++; return transport(); } });
  for (const url of ['http://127.0.0.1/', 'http://[::1]', 'http://[::ffff:8.8.8.8]', 'http://100.100.100.200', 'http://168.63.129.16', 'http://localhost', 'http://metadata.google.internal']) {
    const result = await analyzer.analyze({ url }); assert.equal(result.status, 'blocked'); assert.ok(result.features);
  }
  assert.equal(queries, 0); assert.equal(requests, 0);
});
test('invalid/credential-bearing input is safely rejected without returning any of the raw URL', async () => {
  const analyzer = new UrlAnalyzer(config, { query, transport });
  for (const input of [null, {}, { url: 'file:///private-token' }, { url: 'https://u:secret@example.com/?token=topsecret' }]) {
    const result = await analyzer.analyze(input); assert.equal(result.status, 'failed'); assert.equal(result.url, null);
    assert.ok(!JSON.stringify(result).includes('topsecret')); assert.ok(!JSON.stringify(result).includes('u:secret'));
  }
});
test('DNS and HTTP partial failures preserve the other subsystem', async () => {
  const dnsFailed = await new UrlAnalyzer(config, { query: async () => { throw Object.assign(new Error(), { code: 'ESERVFAIL' }); }, transport }).analyze({ url: 'https://example.com' });
  assert.equal(dnsFailed.status, 'partial'); assert.equal(dnsFailed.http.status, 'completed'); assert.ok(dnsFailed.features);
  const httpFailed = await new UrlAnalyzer(config, { query, transport: async () => { throw Object.assign(new Error('sensitive details'), { code: 'ECONNRESET' }); } }).analyze({ url: 'https://example.com' });
  assert.equal(httpFailed.status, 'partial'); assert.equal(httpFailed.dns.status, 'completed'); assert.ok(!JSON.stringify(httpFailed).includes('sensitive details'));
  const blocked = await new UrlAnalyzer(config, { query, transport: async () => { throw new PolicyError('private DNS answer'); } }).analyze({ url: 'https://example.com' });
  assert.equal(blocked.status, 'blocked'); assert.equal(blocked.dns.status, 'completed');
});
test('IP literals skip DNS record queries rather than fabricating DNS results', async () => {
  let queries = 0;
  const result = await new UrlAnalyzer(config, { query: async () => { queries++; return []; }, transport }).analyze({ url: 'http://8.8.8.8' });
  assert.equal(result.status, 'completed'); assert.equal(result.dns.status, 'skipped'); assert.equal(queries, 0);
});
test('concurrent analyses remain isolated and capacity resets after completion', async () => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const analyzer = new UrlAnalyzer({ ...config, maxConcurrentAnalyses: 2 }, { query, transport: async () => { await gate; return transport(); } });
  const first = analyzer.analyze({ url: 'https://first.example.com/' });
  const second = analyzer.analyze({ url: 'https://second.example.com/' });
  const blocked = await analyzer.analyze({ url: 'https://third.example.com/' });
  assert.equal(blocked.errors[0]?.code, 'CAPACITY_LIMIT'); release();
  const [a, b] = await Promise.all([first, second]);
  assert.notStrictEqual(a.dns, b.dns); assert.notEqual(a.url?.hostname, b.url?.hostname);
  assert.equal((await analyzer.analyze({ url: 'https://fourth.example.com' })).status, 'completed');
});
test('total deadline and caller cancellation stop in-flight DNS/HTTP work', async () => {
  const options = { query: async (_type: unknown, _host: string, signal: AbortSignal) => { await delay(1000, undefined, { signal }); return []; }, transport: async (_url: URL, _method: unknown, signal: AbortSignal) => { await delay(1000, undefined, { signal }); return transport(); } };
  const analyzer = new UrlAnalyzer({ ...config, analysisTimeoutMs: 15 }, options);
  const result = await analyzer.analyze({ url: 'https://example.com' });
  assert.equal(result.status, 'partial'); assert.equal(result.http.status, 'timed_out');
  const cancel = new AbortController(); cancel.abort();
  const cancelled = await analyzer.analyze({ url: 'https://example.com' }, cancel.signal);
  assert.equal(cancelled.http.status, 'cancelled');
});
