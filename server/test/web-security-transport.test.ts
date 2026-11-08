import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import type http from 'node:http';
import { loadConfig } from '../src/modules/web-security/config.js';
import { createTransport, type RequestFactory } from '../src/modules/web-security/network/transport.js';
import { WebSecurityScanner } from '../src/modules/web-security/scanner.js';

const address = '93.184.216.34';
const resolver = async () => [{ address, family: 4 }];
const target = new URL('http://example.com/');
function factory(options: { body?: string; peer?: string; encoding?: string; stall?: boolean; secure?: boolean; authorized?: boolean; status?: number; headers?: Record<string, string>; capture?: (o: http.RequestOptions) => void } = {}): RequestFactory {
  return (_url, init) => {
    options.capture?.(init);
    const request = new EventEmitter() as http.ClientRequest;
    let destroyed = false;
    request.destroy = ((error?: Error) => { if (!destroyed) { destroyed = true; if (error) request.emit('error', error); } return request; }) as http.ClientRequest['destroy'];
    init.signal?.addEventListener('abort', () => request.destroy(new Error('deadline')), { once: true });
    request.end = (() => {
      queueMicrotask(() => {
        const socket = new EventEmitter() as EventEmitter & { remoteAddress: string; authorized?: boolean };
        socket.remoteAddress = options.peer ?? address;
        socket.authorized = options.authorized ?? true;
        request.emit('socket', socket); socket.emit('connect');
        if (options.secure) socket.emit('secureConnect');
        if (destroyed || options.stall) return;
        const response = Object.assign(Readable.from([Buffer.from(options.body ?? 'hello')]), {
          statusCode: options.status ?? 200, headers: { 'content-type': 'text/plain', ...options.headers, ...(options.encoding ? { 'content-encoding': options.encoding } : {}) },
        });
        request.emit('response', response);
      });
      return request;
    }) as http.ClientRequest['end'];
    return request;
  };
}
test('transport pins lookup to validated DNS, disables pooling/proxies and avoids a second DNS lookup', async () => {
  let calls = 0;
  const transport = createTransport(loadConfig({}), async () => { calls++; return resolver(); }, factory({ capture: (o) => {
    assert.equal(o.agent, false); assert.equal(o.family, 4);
    (o.lookup as Function)('example.com', {}, (error: unknown, pinned: string, family: number) => { assert.equal(error, null); assert.equal(pinned, address); assert.equal(family, 4); });
  } }));
  assert.equal((await transport(target, new AbortController().signal)).body, 'hello'); assert.equal(calls, 1);
});
test('connection-time verification rejects a peer different from the validated address', async () => {
  for (const peer of ['127.0.0.1', '169.254.169.254', '8.8.8.8']) {
    const transport = createTransport(loadConfig({}), resolver, factory({ peer }));
    await assert.rejects(transport(target, new AbortController().signal), /verification/);
  }
});
test('each new request revalidates DNS and blocks a public-to-private rebind before connecting', async () => {
  let lookups = 0;
  let connections = 0;
  const transport = createTransport(loadConfig({}), async () => [{ address: ++lookups === 1 ? address : '10.0.0.1', family: 4 }], factory({ capture: () => { connections++; } }));
  await transport(target, new AbortController().signal);
  await assert.rejects(transport(target, new AbortController().signal), /prohibited/);
  assert.equal(connections, 1);
});
test('response size, unsupported encodings and request deadlines are enforced', async () => {
  await assert.rejects(createTransport({ ...loadConfig({}), maxResponseBytes: 3 }, resolver, factory())(target, new AbortController().signal), /size/);
  await assert.rejects(createTransport(loadConfig({}), resolver, factory({ encoding: 'gzip' }))(target, new AbortController().signal), /encoding/);
  await assert.rejects(createTransport({ ...loadConfig({}), requestTimeoutMs: 10 }, resolver, factory({ stall: true }))(target, new AbortController().signal), /deadline/);
});
test('HTTPS retains certificate verification rather than accepting an unauthorized TLS socket', async () => {
  const transport = createTransport(loadConfig({}), resolver, factory({ secure: true, authorized: false }));
  await assert.rejects(transport(new URL('https://example.com/'), new AbortController().signal), /TLS verification/);
});
test('same-origin redirects cannot bypass revalidation when DNS changes to a private address', async () => {
  const config = { ...loadConfig({ WEB_SECURITY_REQUIRE_PASSIVE_AUTH: 'false' }), requestIntervalMs: 1 };
  let lookups = 0;
  let connections = 0;
  const transport = createTransport(config, async () => [{ address: ++lookups === 1 ? address : '127.0.0.1', family: 4 }],
    factory({ status: 302, headers: { location: '/next' }, capture: () => { connections++; } }));
  const result = await new WebSecurityScanner(config, { transport }).scan({ url: target.href });
  assert.equal(result.status, 'partial'); assert.equal(connections, 1); assert.equal(lookups, 2);
});
