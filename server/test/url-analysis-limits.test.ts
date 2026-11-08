import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { Semaphore } from '../src/shared/network/limits.js';
import { loadUrlAnalysisConfig } from '../src/modules/url-analysis/config.js';
import { HttpAnalyzer } from '../src/modules/url-analysis/http/client.js';
import { classifyAddress, PolicyError } from '../src/shared/network/policy.js';
import { structuredError } from '../src/modules/url-analysis/errors.js';

test('semaphore reserves slots correctly, bounds queues, cancels waiters and recovers after errors', async () => {
  const semaphore = new Semaphore(1, 1);
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const signal = new AbortController().signal;
  const first = semaphore.run(signal, () => gate);
  const cancellation = new AbortController();
  const queued = semaphore.run(cancellation.signal, async () => 'queued');
  await assert.rejects(semaphore.run(signal, async () => 'overflow'), /queue limit/);
  cancellation.abort(); await assert.rejects(queued);
  release(); await first;
  await assert.rejects(semaphore.run(signal, async () => { throw new Error('work failed'); }));
  assert.equal(await semaphore.run(signal, async () => 'recovered'), 'recovered');
});
test('semaphore does not exceed concurrency even when many operations finish together', async () => {
  const semaphore = new Semaphore(2); let active = 0; let peak = 0;
  await Promise.all(Array.from({ length: 20 }, () => semaphore.run(new AbortController().signal, async () => {
    active++; peak = Math.max(peak, active); await delay(1); active--;
  })));
  assert.equal(peak, 2); assert.equal(active, 0);
});
test('configuration validates limits, ports and user agents without exposing values', () => {
  for (const env of [{ URL_ANALYSIS_TIMEOUT_MS: '-1' }, { URL_ANALYSIS_ALLOWED_PORTS: '80,99999' }, { URL_ANALYSIS_USER_AGENT: 'secret\r\nCookie: token' }]) {
    assert.throws(() => loadUrlAnalysisConfig(env), (error: unknown) => error instanceof Error && !error.message.includes('token'));
  }
  assert.equal(loadUrlAnalysisConfig({ URL_ANALYSIS_MAX_REDIRECTS: '0' }).maxRedirects, 0);
});
test('special-purpose and IPv4-mapped addresses are classified using the shared conservative policy', () => {
  for (const address of ['0.0.0.0', '127.0.0.1', '169.254.169.254', '168.63.129.16', '10.0.0.1', '100.64.0.1', '192.0.2.1', '224.0.0.1', '::1', 'fc00::1', 'fe80::1', '2001:db8::1', '64:ff9b::808:808', '::ffff:8.8.8.8']) assert.equal(classifyAddress(address).publiclyRoutable, false, address);
  assert.equal(classifyAddress('::ffff:8.8.8.8').mappedIpv4, '8.8.8.8');
});
test('native Undici timeouts are timed_out, and request budgets prevent uncontrolled HEAD fallback', async () => {
  const config = loadUrlAnalysisConfig({}); const target = new URL('https://example.com');
  for (const code of ['UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT', 'ETIMEDOUT']) {
    const result = await new HttpAnalyzer(config, async () => { throw Object.assign(new Error('secret'), { code }); }).analyze(target, new AbortController().signal);
    assert.equal(result.status, 'timed_out'); assert.equal(result.errors[0]?.code, code);
  }
  let calls = 0;
  const result = await new HttpAnalyzer({ ...config, maxHttpRequests: 1 }, async () => { calls++; return { statusCode: 405, headers: {} }; }).analyze(target, new AbortController().signal);
  assert.equal(result.errors[0]?.code, 'REQUEST_LIMIT'); assert.equal(calls, 1);
});
test('nested connection-policy errors remain blocked rather than being hidden by library wrappers', () => {
  const error = structuredError('http', new Error('do not disclose', { cause: new PolicyError('private') }));
  assert.equal(error.code, 'NETWORK_BLOCKED'); assert.equal(error.retryable, false);
});
