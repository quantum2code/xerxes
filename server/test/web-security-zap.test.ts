import assert from 'node:assert/strict';
import test from 'node:test';
import { loadConfig } from '../src/modules/web-security/config.js';
import { createZapBackend, normalizeZapAlerts, toHar } from '../src/modules/web-security/integrations/zap.js';
import type { DockerRunner } from '../src/modules/web-security/integrations/docker.js';
import type { Page } from '../src/modules/web-security/types.js';

const token = 'z'.repeat(40);
const config = { ...loadConfig({}), grants: [{ token, origin: 'https://example.com', modes: ['passive' as const, 'active' as const], expiresAt: '2099-01-01' }] };
const request = { url: 'https://example.com/', authorizationToken: token };
const pages: Page[] = [{ url: request.url, status: 200, headers: { 'content-type': 'text/html', 'set-cookie': ['session=secret; Secure; HttpOnly'] }, body: '<p>hello</p>' }];
const alert = { id: '1', pluginId: '40012', alert: 'Reflected XSS', confidence: 'Medium', risk: 'High', url: 'http://example.com/?q=secret', cweid: '79', param: 'q', evidence: '<script>secret</script>', attack: 'password=secret' };
function mockDocker(options: { unsafe?: boolean; error?: string; badProgress?: boolean } = {}) {
  const calls: { args: string[]; input?: string }[] = [];
  const docker: DockerRunner = async (args, opts) => {
    calls.push({ args, input: opts?.input });
    if (options.error && args[0] === options.error) throw new Error('sensitive daemon error');
    if (args[0] === 'info') return 'linux';
    if (args[0] === 'inspect') return JSON.stringify([{ HostConfig: { NetworkMode: options.unsafe ? 'bridge' : 'none', ReadonlyRootfs: true, CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges'] } }]);
    if (args[0] === 'logs') return JSON.stringify({ forwarded: 1, denied: 0, failures: 0, exhausted: false });
    if (args[0] === 'exec' && opts?.input?.startsWith('{"url":')) {
      const url = new URL(JSON.parse(opts.input).url);
      const method = url.pathname.split('/').filter(Boolean).at(-1);
      switch (method) {
        case 'version': return '{"version":"2.17.0"}';
        case 'recordsToScan': return options.badProgress ? '{}' : '{"recordsToScan":"0"}';
        case 'alerts': return JSON.stringify({ alerts: [{ ...alert, url: 'https://example.com/' }] });
        case 'newContext': return '{"contextId":"1"}';
        case 'scan': return '{"scan":"0"}';
        case 'status': return '{"status":"100"}';
        case 'alertsIds': return '{"alertsIds":["1"]}';
        case 'alert': return JSON.stringify({ alert });
        default: return '{"Result":"OK"}';
      }
    }
    return '';
  };
  return { docker, calls };
}
test('ZAP availability errors return structured unavailable without invoking worker', async () => {
  const { docker, calls } = mockDocker({ error: 'info' });
  const result = await createZapBackend(config, docker)(request, pages, 9, new AbortController().signal);
  assert.equal(result.status, 'unavailable'); assert.equal(calls.length, 1);
  assert.ok(!JSON.stringify(result).includes('sensitive daemon'));
});
test('passive ZAP imports HAR in network-none worker without any active API or gateway', async () => {
  const { docker, calls } = mockDocker();
  const result = await createZapBackend(config, docker)(request, pages, 9, new AbortController().signal);
  assert.equal(result.status, 'completed'); assert.equal(result.findings.length, 1);
  assert.ok(calls.some((c) => c.args.includes('--network') && c.args.includes('none')));
  assert.ok(!calls.some((c) => c.args[0] === 'volume'));
  assert.ok(!calls.some((c) => c.input?.includes('/ascan/')));
  assert.ok(calls.some((c) => c.args[0] === 'rm'));
});
test('active ZAP uses policy gateway, only selected rules, and cleans all scan resources', async () => {
  const { docker, calls } = mockDocker();
  const result = await createZapBackend(config, docker)({ ...request, mode: 'active' }, pages, 9, new AbortController().signal);
  assert.equal(result.status, 'completed'); assert.equal(result.findings[0]?.affectedUrl.startsWith('https://example.com/'), true);
  assert.ok(calls.some((c) => c.args[0] === 'run' && c.args.some((a) => a.startsWith('XERXES_GATEWAY_POLICY='))));
  const apiCalls = calls.filter((c) => c.input?.startsWith('{"url":')).map((c) => new URL(JSON.parse(c.input!).url));
  assert.equal(apiCalls.find((u) => u.pathname.includes('enableScanners'))?.searchParams.get('ids'), '40012,40018,10028');
  assert.equal(apiCalls.find((u) => u.pathname.endsWith('/scan/'))?.searchParams.get('recurse'), 'false');
  assert.equal(calls.filter((c) => c.args[0] === 'rm').length, 2);
  assert.ok(calls.some((c) => c.args[0] === 'volume' && c.args[1] === 'rm'));
});
test('ZAP fails closed on sandbox mismatch or malformed progress, with cleanup', async () => {
  for (const opts of [{ unsafe: true }, { badProgress: true }]) {
    const { docker, calls } = mockDocker(opts);
    const result = await createZapBackend(config, docker)(request, pages, 9, new AbortController().signal);
    assert.equal(result.status, 'blocked'); assert.ok(calls.some((c) => c.args[0] === 'rm'));
  }
});
test('active authorization and request budgets are enforced before Docker work', async () => {
  const { docker, calls } = mockDocker();
  const backend = createZapBackend(config, docker);
  await assert.rejects(backend({ url: request.url, mode: 'active' }, pages, 9, new AbortController().signal));
  assert.equal((await backend({ ...request, mode: 'active' }, pages, 0, new AbortController().signal)).status, 'blocked');
  assert.equal(calls.length, 0);
});
test('ZAP risk/confidence mapping rejects false positives and out-of-scope alerts without leaking attack content', () => {
  const findings = normalizeZapAlerts([alert, { ...alert, confidence: 'False Positive' }, { ...alert, url: 'http://evil.example/' }], new URL(request.url), 'http://example.com');
  assert.equal(findings.length, 1); assert.equal(findings[0]?.severity, 'high'); assert.equal(findings[0]?.confidence, 'medium');
  assert.deepEqual(findings[0]?.owasp, ['A03:2021']);
  assert.ok(!JSON.stringify(findings).includes('password=secret'));
  assert.throws(() => normalizeZapAlerts({}, new URL(request.url)));
});
test('HAR redacts cookie values, query values and common credential markers', () => {
  const har = toHar([{ ...pages[0]!, url: 'https://example.com/?token=topsecret', body: '{"password":"hunter2"}' }]);
  assert.ok(!har.includes('session=secret')); assert.ok(!har.includes('topsecret')); assert.ok(!har.includes('hunter2'));
  assert.ok(har.includes('HttpOnly'));
});
test('cleanup errors cannot silently produce completed backend status', async () => {
  const { docker } = mockDocker({ error: 'rm' });
  const result = await createZapBackend(config, docker)(request, pages, 9, new AbortController().signal);
  assert.equal(result.status, 'failed');
  assert.ok(result.limitations.some((reason) => reason.includes('cleanup incomplete')));
});
