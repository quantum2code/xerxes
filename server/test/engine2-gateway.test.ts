import assert from 'node:assert/strict';
import http from 'node:http';
import tls from 'node:tls';
import type { Socket } from 'node:net';
import { once } from 'node:events';
import test from 'node:test';
import { buildConnector, MockAgent, request as send } from 'undici';
import { createPolicyGateway } from '../src/engines/engine2/zap/gateway.js';
import { createForwarder, pinnedGatewayConnector, type GatewayPolicy } from '../src/engines/engine2/zap/gateway-transport.js';
import { config } from './helpers/engine2.js';

function policy(): GatewayPolicy {
  const rules = config().grants[0]!.rules;
  return { rules: { ...rules, protocols: ['http:', 'https:'], ports: [80, 443], activeMethods: ['GET', 'HEAD', 'POST'] }, mode: 'active', expiresAt: Date.now() + 30000, labAddresses: [] };
}
test('real HTTPS interception preserves HTTPS scope and blocks excluded paths before forwarding', { timeout: 10000 }, async (t) => {
  const forwarded: string[] = [];
  const gateway = await createPolicyGateway(policy(), { ...config(), requestIntervalMs: 1 }, { forward: async (url) => {
    forwarded.push(url.href); return { status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('scoped HTTPS response') };
  } });
  gateway.server.listen(0, '127.0.0.1'); await once(gateway.server, 'listening'); t.after(() => gateway.close());
  const port = (gateway.server.address() as { port: number }).port;
  const tunnel = (path: string) => new Promise<string>((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, method: 'CONNECT', path: 'staging.example.com:443' });
    req.on('error', reject);
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); reject(new Error('CONNECT rejected')); return; }
      const secure = tls.connect({ socket, ca: gateway.certificate, servername: 'staging.example.com', rejectUnauthorized: true });
      let text = '';
      secure.on('error', reject); secure.on('data', (chunk) => { text += chunk; }); secure.on('end', () => resolve(text));
      secure.once('secureConnect', () => { assert.equal(secure.authorized, true); secure.write(`GET ${path} HTTP/1.1\r\nHost: staging.example.com:443\r\nConnection: close\r\n\r\n`); });
    }); req.end();
  });
  assert.ok((await tunnel('/app/child')).includes('scoped HTTPS response'));
  const denied = await tunnel('/app/private').catch(() => '');
  assert.ok(!denied.includes('scoped HTTPS response'));
  assert.deepEqual(forwarded, ['https://staging.example.com/app/child']); assert.ok(gateway.stats.denied > 0);
});
test('gateway enforces scope, method phase, body/request limits, and omits credential headers', { timeout: 10000 }, async (t) => {
  let phase: 'crawl' | 'active' = 'crawl'; const calls: { url: string; headers: Record<string, string> }[] = [];
  const cfg = { ...config(), requestIntervalMs: 1, maxRequests: 1 };
  const gateway = await createPolicyGateway(policy(), cfg, { phase: () => ({ mode: phase, expiresAt: Date.now() + 30000 }), forward: async (url, _method, headers) => {
    calls.push({ url: url.href, headers }); return { status: 200, headers: {}, body: Buffer.from('ok') };
  } });
  gateway.server.listen(0, '127.0.0.1'); await once(gateway.server, 'listening'); t.after(() => gateway.close());
  const port = (gateway.server.address() as { port: number }).port;
  const post = (path: string, method = 'POST') => new Promise<number>((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path, method, headers: { authorization: 'Bearer secret', cookie: 'session=secret', 'content-type': 'text/plain' } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode!)); }); req.on('error', reject); req.end('test');
  });
  await assert.rejects(post('http://staging.example.com/app'));
  await assert.rejects(post('http://169.254.169.254/', 'GET'));
  assert.equal(calls.length, 0); phase = 'active';
  assert.equal(await post('http://staging.example.com/app'), 200);
  assert.deepEqual(calls[0]?.headers, { 'content-type': 'text/plain' });
  await assert.rejects(post('http://staging.example.com/app'));
  assert.equal(calls.length, 1); assert.equal(gateway.stats.exhausted, true);
});
test('fresh DNS validation and response-size bounds are enforced by the real Undici forwarding wrapper', async (t) => {
  const mock = new MockAgent(); mock.disableNetConnect(); t.after(() => mock.close());
  const target = new URL('http://staging.example.com/app');
  mock.get(target.origin).intercept({ path: '/app', method: 'GET' }).reply(200, 'fixture');
  let phase = 0; let requests = 0;
  const forward = createForwarder(policy(), config(), async () => [{ address: phase ? '127.0.0.1' : '8.8.8.8', family: 4 }], (url, options) => { requests++; return send(url, { ...options, dispatcher: mock }); });
  assert.equal((await forward(target, 'GET', {}, Buffer.alloc(0), new AbortController().signal)).body.toString(), 'fixture');
  phase = 1; await assert.rejects(forward(target, 'GET', {}, Buffer.alloc(0), new AbortController().signal)); assert.equal(requests, 1);
  mock.get(target.origin).intercept({ path: '/app', method: 'GET' }).reply(200, 'x'.repeat(100));
  const bounded = createForwarder(policy(), { ...config(), maxResponseBytes: 10 }, async () => [{ address: '8.8.8.8', family: 4 }], (url, options) => send(url, { ...options, dispatcher: mock }));
  await assert.rejects(bounded(target, 'GET', {}, Buffer.alloc(0), new AbortController().signal), /Response size/);
});
test('gateway connector never passes mismatched or unverified peers to Undici', async () => {
  for (const peer of ['127.0.0.1', '169.254.169.254', '1.1.1.1']) {
    let destroyed = false;
    const builder: typeof buildConnector = () => (_options, callback) => callback(null, { remoteAddress: peer, authorized: true, destroy() { destroyed = true; } } as unknown as Socket);
    const connector = pinnedGatewayConnector(new URL('https://staging.example.com'), { address: '8.8.8.8', family: 4 }, policy(), config(), builder);
    await new Promise<void>((resolve) => connector({ hostname: 'staging.example.com', protocol: 'https:', port: '443' }, (error, socket) => { assert.ok(error); assert.equal(socket, null); resolve(); }));
    assert.equal(destroyed, true);
  }
});
