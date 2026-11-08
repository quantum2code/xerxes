import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import test from 'node:test';
import { createGateway } from '../src/modules/web-security/network/gateway.js';
import { loadConfig } from '../src/modules/web-security/config.js';
import type { Transport } from '../src/modules/web-security/network/transport.js';

const config = { ...loadConfig({}), requestIntervalMs: 1 };
async function fixture(t: { after(fn: () => void): void }, transport: Transport, maxRequests = 2) {
  const gateway = createGateway({ origin: 'https://example.com', proxyOrigin: 'http://example.com', maxRequests, expiresAt: Date.now() + 10_000 }, config, transport);
  gateway.server.listen(0, '127.0.0.1'); await once(gateway.server, 'listening');
  t.after(() => { gateway.server.closeAllConnections(); gateway.server.close(); });
  const address = gateway.server.address() as { port: number };
  const send = (path: string, method = 'GET', headers: Record<string, string> = {}, body?: string) => new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port: address.port, path, method, headers }, (res) => {
      let text = ''; res.on('data', (c) => { text += c; }); res.on('end', () => resolve({ status: res.statusCode!, body: text }));
    });
    req.on('error', reject); req.end(body);
  });
  return { ...gateway, send, port: address.port };
}
test('gateway pins scope, maps HTTPS upstream and strips arbitrary credentials/headers', async (t) => {
  let calls = 0;
  const g = await fixture(t, async (url, _signal, init) => {
    calls++; assert.equal(url.href, 'https://example.com/login?q=1');
    assert.deepEqual(Object.keys(init!).sort(), ['body', 'contentType', 'method']);
    return { url: url.href, status: 200, headers: {}, body: 'ok' };
  });
  assert.equal((await g.send('http://example.com/login?q=1', 'POST', { authorization: 'Bearer secret', cookie: 'secret=yes', host: 'evil.example', 'content-type': 'text/plain' }, 'test')).status, 200);
  for (const path of ['http://127.0.0.1/', 'http://other.example/', 'https://example.com/', '/relative', 'http://example.com:8080/', 'http://example.com//evil.example/']) assert.ok((await g.send(path)).status >= 400);
  assert.equal(calls, 1);
});
test('gateway budgets are hard limits even for repeated URLs and unsafe methods', async (t) => {
  let calls = 0;
  const g = await fixture(t, async (url) => { calls++; return { url: url.href, status: 200, headers: {}, body: '' }; }, 1);
  assert.equal((await g.send('http://example.com/')).status, 200);
  assert.equal((await g.send('http://example.com/')).status, 429);
  assert.equal((await g.send('http://example.com/', 'DELETE')).status, 403);
  assert.equal(calls, 1); assert.equal(g.state.exhausted, true);
});
test('gateway never follows cross-scope redirects and blocks CONNECT', async (t) => {
  let calls = 0;
  const g = await fixture(t, async (url) => { calls++; return { url: url.href, status: 302, headers: { location: 'http://169.254.169.254/' }, body: '' }; });
  assert.equal((await g.send('http://example.com/')).status, 302);
  assert.equal((await g.send('http://169.254.169.254/')).status, 403);
  assert.equal(calls, 1);
  const code = await new Promise<number>((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port: g.port, method: 'CONNECT', path: 'example.com:443' });
    req.on('connect', (res, socket) => { resolve(res.statusCode!); socket.destroy(); }); req.on('error', reject); req.end();
  });
  assert.equal(code, 403);
  assert.equal(g.state.failures, 0);
});
test('gateway refuses expired or mismatched policies', () => {
  assert.throws(() => createGateway({ origin: 'https://example.com', proxyOrigin: 'http://evil.example', maxRequests: 1, expiresAt: Date.now() + 1000 }, config));
});
