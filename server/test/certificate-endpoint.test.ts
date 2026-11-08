import assert from 'node:assert/strict';
import { once } from 'node:events';
import test from 'node:test';
import type { TestContext } from 'node:test';
import { createApp } from '../src/app.js';
import type { CertificateTask } from '../src/modules/certificate-validation/index.js';

async function serve(t: TestContext, certificate?: CertificateTask) {
  const server = createApp(certificate ? { certificate } : {}).listen(0, '127.0.0.1');
  t.after(() => new Promise<void>((resolve, reject) => { server.close((error) => error ? reject(error) : resolve()); }));
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return `http://127.0.0.1:${address.port}`;
}
const post = (base: string, body: string, type = 'application/json') =>
  fetch(`${base}/api/certificate`, { method: 'POST', headers: { 'Content-Type': type }, body });

test('POST /api/certificate returns the Engine 3 result and passes only the url to the task', async (t) => {
  const seen: unknown[] = [];
  const base = await serve(t, async (input) => {
    seen.push(input);
    return { status: 'ok', valid: false, findings: [{ id: 'cert.expired', severity: 'high', message: 'x', category: 'validity' }] };
  });
  const response = await post(base, JSON.stringify({ url: 'https://example.com', authorizationToken: 'secret', extra: 1 }));
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type')!, /application\/json/);
  assert.deepEqual(await response.json(), { status: 'ok', valid: false, findings: [{ id: 'cert.expired', severity: 'high', message: 'x', category: 'validity' }] });
  assert.deepEqual(seen, [{ url: 'https://example.com' }]);
});

test('malformed requests are rejected before the task runs, with the same error shape as /api/analyze', async (t) => {
  let calls = 0;
  const base = await serve(t, async () => { calls++; return { status: 'ok', valid: true, findings: [] }; });
  for (const body of ['[]', '{}', '{"url":5}', '{"url":null}']) {
    const response = await post(base, body);
    assert.equal(response.status, 400, body);
    assert.deepEqual(await response.json(), { error: { code: 'invalid_input', message: 'Provide an object with a string url' } });
  }
  const broken = await post(base, '{"url": ');
  assert.equal(broken.status, 400);
  assert.equal(((await broken.json()) as { error: { code: string } }).error.code, 'invalid_json');
  assert.equal((await post(base, '{"url":"https://example.com"}', 'text/plain')).status, 415);
  assert.equal(calls, 0);
});

test('only POST is exposed, and the real task never connects for skipped or guarded targets', async (t) => {
  const base = await serve(t);
  assert.equal((await fetch(`${base}/api/certificate`)).status, 404);
  const skipped = await (await post(base, '{"url":"http://example.com"}')).json() as { status: string; valid: null };
  assert.deepEqual([skipped.status, skipped.valid], ['skipped', null]);
  for (const url of ['https://127.0.0.1', 'https://169.254.169.254', 'https://localhost', 'https://user:pw@example.com']) {
    const blocked = await (await post(base, JSON.stringify({ url }))).json() as { status: string; valid: null };
    assert.deepEqual([blocked.status, blocked.valid], ['blocked', null], url);
  }
});