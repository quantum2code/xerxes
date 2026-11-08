import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import type { LookupAddress } from 'node:dns';
import type { ClientRequest, IncomingMessage } from 'node:http';
import {
  createSafeHttpRedirectTransport,
  detectHttpRedirects,
} from '../src/modules/threat-detection/http-redirect/index.js';
import type {
  HttpRedirectRequest,
  HttpRedirectResponse,
  HttpRedirectTransport,
} from '../src/modules/threat-detection/http-redirect/index.js';

function scripted(responses: HttpRedirectResponse[]) {
  const calls: string[] = [];
  const transport: HttpRedirectTransport = async (url) => {
    calls.push(url.href);
    const response = responses[calls.length - 1];
    assert.ok(response, 'Unexpected extra request');
    return response;
  };
  return { calls, transport };
}

// This seam never creates a socket. It exposes the actual safe transport's request options.
function socketStub(inspect: HttpRedirectRequest = () => { throw new Error('Unused'); }) {
  let destroyed = false;
  let ended = false;
  let calls = 0;
  const request: HttpRedirectRequest = (url, options, onResponse) => {
    calls++;
    inspect(url, options, onResponse);
    const req = Object.assign(new EventEmitter(), {
      end() {
        ended = true;
        queueMicrotask(() => onResponse({ statusCode: 200, headers: {} } as IncomingMessage));
      },
      destroy() { destroyed = true; return req; },
    });
    return req as unknown as ClientRequest;
  };
  return { request, get destroyed() { return destroyed; }, get ended() { return ended; }, get calls() { return calls; } };
}

const noInspect: HttpRedirectRequest = () => ({} as ClientRequest);

test('follows all supported redirects, resolves relative locations, and records headers', async () => {
  const fake = scripted([
    { statusCode: 301, location: '/one' },
    { statusCode: 302, location: 'two' },
    { statusCode: 303, location: '?next=1' },
    { statusCode: 307, location: '//example.com/four' },
    { statusCode: 308, location: '/done#fragment' },
    { statusCode: 200 },
  ]);
  const result = await detectHttpRedirects('https://example.com/start#ignored', fake);
  assert.equal(result.status, 'complete');
  assert.equal(result.error, null);
  assert.equal(result.finalUrl, 'https://example.com/done');
  assert.deepEqual(fake.calls, [
    'https://example.com/start', 'https://example.com/one', 'https://example.com/two',
    'https://example.com/two?next=1', 'https://example.com/four', 'https://example.com/done',
  ]);
  assert.deepEqual(result.chain[0], { url: fake.calls[0], statusCode: 301, location: '/one',
    redirect: { url: 'https://example.com/one', crossDomain: false, followed: true } });
  assert.deepEqual(result.chain.at(-1), { url: result.finalUrl, statusCode: 200, location: null });
  assert.equal(result.crossDomain, false);
  assert.equal(result.httpsDowngrade, false);
});

test('signals registrable-domain changes and HTTPS downgrade, not sibling subdomains', async () => {
  const sameDomain = scripted([{ statusCode: 302, location: 'https://b.example.co.uk/' }, { statusCode: 200 }]);
  assert.equal((await detectHttpRedirects('https://a.example.co.uk', sameDomain)).crossDomain, false);
  const changed = scripted([{ statusCode: 302, location: 'http://example.org/' }, { statusCode: 200 }]);
  const result = await detectHttpRedirects('https://example.com', changed);
  assert.equal(result.crossDomain, true);
  assert.equal(result.httpsDowngrade, true);
  const ipChange = scripted([{ statusCode: 302, location: 'https://1.1.1.1/' }, { statusCode: 200 }]);
  assert.equal((await detectHttpRedirects('https://8.8.8.8', ipChange)).crossDomain, true);
});

test('only supported redirect statuses with Location are followed', async () => {
  for (const response of [{ statusCode: 300, location: '/ignored' }, { statusCode: 304, location: '/ignored' }, { statusCode: 302 }, { statusCode: 500 }]) {
    const fake = scripted([response]);
    const result = await detectHttpRedirects('https://example.com', fake);
    assert.equal(result.status, 'complete');
    assert.equal(fake.calls.length, 1);
  }
});

test('canonical loops include fragments, default ports, and trailing hostname dots', async () => {
  for (const target of ['#fragment', 'https://example.com:443/', 'https://example.com./']) {
    const fake = scripted([{ statusCode: 302, location: target }]);
    const result = await detectHttpRedirects('https://example.com', fake);
    assert.equal(result.status, 'loop');
    assert.equal(result.error?.code, 'loop');
    assert.equal(fake.calls.length, 1);
    assert.equal(result.chain[0]?.redirect?.followed, false);
  }
  const fake = scripted([{ statusCode: 301, location: '/b' }, { statusCode: 302, location: '/' }]);
  const result = await detectHttpRedirects('https://example.com', fake);
  assert.equal(result.status, 'loop');
  assert.deepEqual(result.chain.map((hop) => hop.redirect?.followed), [true, false]);
});

test('redirect limit counts redirects, not the initial request', async () => {
  const zero = scripted([{ statusCode: 302, location: '/next' }]);
  const result = await detectHttpRedirects('https://example.com', { ...zero, maxRedirects: 0 });
  assert.equal(result.status, 'limit');
  assert.equal(result.finalUrl, 'https://example.com/next');
  assert.equal(zero.calls.length, 1);
  assert.deepEqual(result.chain[0]?.redirect, { url: 'https://example.com/next', crossDomain: false, followed: false });
  const one = scripted([{ statusCode: 302, location: '/next' }, { statusCode: 200 }]);
  assert.equal((await detectHttpRedirects('https://example.com', { ...one, maxRedirects: 1 })).status, 'complete');
  const over = scripted([{ statusCode: 302, location: '/next' }, { statusCode: 302, location: '/third' }]);
  assert.equal((await detectHttpRedirects('https://example.com', { ...over, maxRedirects: 1 })).status, 'limit');
  assert.equal(over.calls.length, 2);
});

test('validates bounded integer options before transport', async () => {
  const fake = scripted([]);
  for (const maxRedirects of [-1, 51, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER]) {
    const result = await detectHttpRedirects('https://example.com', { ...fake, maxRedirects });
    assert.equal(result.error?.code, 'invalid-options');
  }
  for (const timeoutMs of [0, -1, 120001, 1.5, NaN, Infinity]) {
    assert.equal((await detectHttpRedirects('https://example.com', { ...fake, timeoutMs })).error?.code, 'invalid-options');
  }
  assert.equal(fake.calls.length, 0);
});

test('blocks unsafe initial URLs and redirect targets even with trusted transport', async () => {
  for (const unsafe of ['ftp://example.com/', 'file:///etc/passwd', 'https://user:pass@example.com/', 'http://example.com:8080/', 'https://example.com:80/', 'http://example.com:443/']) {
    const initial = scripted([]);
    assert.equal((await detectHttpRedirects(unsafe, initial)).status, 'blocked', unsafe);
    assert.equal(initial.calls.length, 0);
    const redirect = scripted([{ statusCode: 302, location: unsafe }]);
    const result = await detectHttpRedirects('https://example.com', redirect);
    assert.equal(result.status, 'blocked', unsafe);
    assert.equal(result.chain.length, 1);
    assert.equal(redirect.calls.length, 1);
  }
  const allowed = scripted([{ statusCode: 200 }]);
  assert.equal((await detectHttpRedirects('http://example.com:80', allowed)).status, 'complete');
});

test('invalid input, invalid Location, and network failures are explicit inconclusive errors', async () => {
  assert.equal((await detectHttpRedirects('not a URL', scripted([]))).error?.code, 'invalid-url');
  const invalid = scripted([{ statusCode: 302, location: 'http://[' }]);
  assert.equal((await detectHttpRedirects('https://example.com', invalid)).error?.code, 'invalid-url');
  const result = await detectHttpRedirects('https://example.com', { transport: async () => { throw new Error('connection failed'); } });
  assert.equal(result.status, 'error');
  assert.equal(result.error?.code, 'network');
  assert.match(result.error!.message, /connection failed/);
  const typeError = await detectHttpRedirects('https://example.com', { transport: async () => { throw new TypeError('socket failure'); } });
  assert.equal(typeError.error?.code, 'network');
});

test('timeout bounds even a transport that ignores cancellation', async () => {
  let signal: AbortSignal | undefined;
  const result = await detectHttpRedirects('https://example.com', {
    timeoutMs: 15,
    transport: async (_url, context) => { signal = context.signal; return new Promise(() => {}); },
  });
  assert.equal(result.status, 'error');
  assert.equal(result.error?.code, 'timeout');
  assert.equal(signal?.aborted, true);
});

test('safe transport rejects nonpublic IPv4, IPv6, and mapped literals without DNS or sockets', async () => {
  let dnsCalls = 0;
  const transport = createSafeHttpRedirectTransport({
    lookup: async () => { dnsCalls++; return []; },
    request: () => { throw new Error('Must not create a socket'); },
  });
  for (const address of [
    '0.0.0.0', '127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.0.1', '169.254.169.254',
    '100.64.0.1', '192.0.2.1', '198.18.0.1', '224.0.0.1', '255.255.255.255',
    '[::]', '[::1]', '[fc00::1]', '[fe80::1]', '[ff02::1]', '[2001:db8::1]',
    '[::ffff:127.0.0.1]', '[::ffff:10.0.0.1]', '[::ffff:192.168.0.1]',
    '2130706433', '0x7f000001',
  ]) {
    const result = await detectHttpRedirects(`http://${address}/`, { transport });
    assert.equal(result.status, 'blocked', address);
    assert.equal(result.error?.code, 'unsafe-address', address);
  }
  assert.equal(dnsCalls, 0);
});

test('safe transport accepts public IPv4, IPv6, and mapped IPv4 literals', async () => {
  const socket = socketStub(noInspect);
  const transport = createSafeHttpRedirectTransport({
    lookup: async () => { throw new Error('Literal must not resolve'); }, request: socket.request,
  });
  for (const address of ['8.8.8.8', '[2606:4700:4700::1111]', '[::ffff:8.8.8.8]']) {
    assert.equal((await detectHttpRedirects(`https://${address}`, { transport })).status, 'complete', address);
  }
  assert.equal(socket.calls, 3);
  assert.equal(socket.destroyed, true);
  assert.equal(socket.ended, true);
});

test('DNS rejects private, mixed, empty, malformed, and mapped-private answers before connecting', async () => {
  const answerSets: LookupAddress[][] = [
    [{ address: '127.0.0.1', family: 4 }],
    [{ address: '8.8.8.8', family: 4 }, { address: '10.0.0.1', family: 4 }],
    [{ address: '::ffff:127.0.0.1', family: 6 }, { address: '8.8.8.8', family: 4 }],
    [{ address: '2606:4700:4700::1111', family: 6 }, { address: 'fc00::1', family: 6 }],
    [], [{ address: 'bad', family: 4 }], [{ address: '8.8.8.8', family: 6 }],
  ];
  for (const answers of answerSets) {
    const transport = createSafeHttpRedirectTransport({
      lookup: async () => answers,
      request: () => { throw new Error('Unsafe answers must not reach a socket'); },
    });
    assert.equal((await detectHttpRedirects('https://example.com', { transport })).status, 'blocked');
  }
});

test('pins both lookup callback forms and preserves GET/TLS hostname without cookies/auth', async () => {
  let dnsCalls = 0;
  const socket = socketStub((url, options) => {
    assert.equal(url.href, 'https://example.com/');
    assert.equal(options.method, 'GET');
    assert.equal(options.agent, false);
    assert.equal(options.hostname, 'example.com');
    assert.equal(options.servername, 'example.com');
    assert.equal(options.rejectUnauthorized, true);
    assert.equal(options.checkServerIdentity, undefined);
    assert.equal(options.auth, undefined);
    assert.deepEqual(options.headers, { accept: '*/*' });

    assert.equal(options.family, 4);
    assert.ok(options.lookup);
    const lookup = options.lookup as (host: string, opts: { all: boolean }, callback: (...args: unknown[]) => void) => void;
    lookup('example.com', { all: false }, (...args) => assert.deepEqual(args, [null, '8.8.8.8', 4]));
    lookup('example.com', { all: true }, (...args) => assert.deepEqual(args, [null, [{ address: '8.8.8.8', family: 4 }]]));
    return {} as ClientRequest;
  });
  const transport = createSafeHttpRedirectTransport({
    lookup: async (hostname) => {
      assert.equal(hostname, 'example.com');
      dnsCalls++;
      return dnsCalls === 1 ? [{ address: '8.8.8.8', family: 4 }, { address: '1.1.1.1', family: 4 }] : [{ address: '127.0.0.1', family: 4 }];
    },
    request: socket.request,
  });
  assert.equal((await detectHttpRedirects('https://example.com', { transport })).status, 'complete');
  assert.equal(dnsCalls, 1, 'Socket lookup must not resolve DNS again');
  assert.equal(socket.destroyed, true, 'Request must be destroyed as soon as headers arrive');
});

test('every hop revalidates DNS, including repeated hostname rebinding', async () => {
  let dnsCalls = 0;
  let requests = 0;
  const transport = createSafeHttpRedirectTransport({
    lookup: async () => [{ address: ++dnsCalls === 1 ? '8.8.8.8' : '127.0.0.1', family: 4 }],
    request: (_url, _options, callback) => {
      requests++;
      const req = Object.assign(new EventEmitter(), {
        end() { queueMicrotask(() => callback({ statusCode: 302, headers: { location: '/next' } } as IncomingMessage)); },
        destroy() { return req; },
      });
      return req as unknown as ClientRequest;
    },
  });
  const result = await detectHttpRedirects('https://example.com', { transport });
  assert.equal(result.status, 'blocked');
  assert.equal(result.chain.length, 1);
  assert.equal(result.finalUrl, 'https://example.com/next');
  assert.equal(dnsCalls, 2);
  assert.equal(requests, 1);
});

test('DNS timeout prevents late answers from creating sockets; DNS errors are inconclusive', async () => {
  let resolveDns!: (answers: LookupAddress[]) => void;
  let requests = 0;
  const transport = createSafeHttpRedirectTransport({
    lookup: () => new Promise((resolve) => { resolveDns = resolve; }),
    request: () => { requests++; throw new Error('No socket allowed'); },
  });
  const result = await detectHttpRedirects('https://example.com', { transport, timeoutMs: 15 });
  assert.equal(result.error?.code, 'timeout');
  resolveDns([{ address: '8.8.8.8', family: 4 }]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(requests, 0);
  const failedDns = createSafeHttpRedirectTransport({ lookup: async () => { throw new Error('DNS failed'); } });
  assert.equal((await detectHttpRedirects('https://example.com', { transport: failedDns })).error?.code, 'network');
});

test('one shared deadline covers DNS and HTTP and cancels the request', async () => {
  let requestSignal: AbortSignal | undefined;
  let destroyed = false;
  const transport = createSafeHttpRedirectTransport({
    lookup: async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      return [{ address: '8.8.8.8', family: 4 }];
    },
    request: (_url, options) => {
      requestSignal = options.signal;
      const req = Object.assign(new EventEmitter(), {
        end() {},
        destroy() { destroyed = true; return req; },
      });
      options.signal!.addEventListener('abort', () => {
        req.destroy();
        req.emit('error', options.signal!.reason);
      }, { once: true });
      return req as unknown as ClientRequest;
    },
  });
  const result = await detectHttpRedirects('https://example.com', { transport, timeoutMs: 100 });
  assert.equal(result.error?.code, 'timeout');
  assert.equal(requestSignal?.aborted, true);
  assert.equal(destroyed, true);
});

test('safe transport reports request errors without fabricating a completed hop', async () => {
  const transport = createSafeHttpRedirectTransport({
    lookup: async () => [{ address: '8.8.8.8', family: 4 }],
    request: () => {
      const req = Object.assign(new EventEmitter(), {
        end() { queueMicrotask(() => req.emit('error', new Error('TLS verification failed'))); },
        destroy() { return req; },
      });
      return req as unknown as ClientRequest;
    },
  });
  const result = await detectHttpRedirects('https://example.com', { transport });
  assert.equal(result.status, 'error');
  assert.equal(result.error?.code, 'network');
  assert.equal(result.chain.length, 0);
});

test('safe transport enforces URL safety when used directly', async () => {
  const transport = createSafeHttpRedirectTransport({ lookup: async () => { throw new Error('Must not resolve'); } });
  for (const url of ['ftp://example.com', 'https://user@example.com', 'https://example.com:8443']) {
    await assert.rejects(transport(new URL(url), { signal: new AbortController().signal }), /Only HTTP|Credentials/);
  }
});
