import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { createServer, type Socket } from 'node:net';
import test from 'node:test';
import { connectTls, createCertificateTask, validateCertificate, type Connector } from '../src/modules/certificate-validation/index.js';
import { GOOD_CERT } from './fixtures/certificates.js';

const good = new X509Certificate(GOOD_CERT);
const now = () => new Date(new Date(good.validFrom).getTime() + 10 * 86_400_000);
const publicResolver = async () => [{ address: '8.8.8.8', family: 4 }];

function setup(connect?: Connector) {
  const calls: Parameters<Connector>[0][] = [];
  const connector: Connector = connect ?? (async () => ({ cert: good, authorized: true }));
  const task = createCertificateTask({
    resolver: publicResolver,
    now,
    connect: async (target, timeout) => { calls.push(target); return connector(target, timeout); },
  });
  return { task, calls };
}

test('a good certificate for the requested host is valid', async () => {
  const { task } = setup();
  const result = await task({ url: 'https://example.com/login#section' });
  assert.equal(result.status, 'ok');
  assert.equal(result.valid, true);
  assert.deepEqual(result.findings, []);
  assert.equal(result.details?.keyBits, 2048);
  assert.ok(result.coverageLimitations?.some((text) => text.includes('Revocation')));
});

test('connects to the pinned IP and keeps the original name for SNI', async () => {
  const { task, calls } = setup();
  await task({ url: 'https://example.com' });
  assert.deepEqual(calls, [{ hostname: 'example.com', address: '8.8.8.8', port: 443 }]);
});

test('a certificate for another host is reported', async () => {
  const { task } = setup();
  const result = await task({ url: 'https://evil.example.org' });
  assert.equal(result.valid, false);
  assert.deepEqual(result.findings.map((f) => f.id), ['cert.hostname_mismatch']);
});

test('the handshake trust error is passed to the evaluator', async () => {
  const { task } = setup(async () => ({ cert: good, authorized: false, authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' }));
  const result = await task({ url: 'https://example.com' });
  assert.equal(result.valid, false);
  assert.equal(result.trustError, 'UNABLE_TO_VERIFY_LEAF_SIGNATURE');
  assert.deepEqual(result.findings.map((f) => f.id), ['cert.untrusted_chain']);
});

test('plain http is skipped without connecting', async () => {
  const { task, calls } = setup();
  const result = await task({ url: 'http://example.com' });
  assert.deepEqual([result.status, result.valid], ['skipped', null]);
  assert.equal(calls.length, 0);
});

test('bad input returns an error result and never connects', async () => {
  const { task, calls } = setup();
  for (const input of [undefined, null, 'https://example.com', {}, { url: 42 }, { url: 'not a url' }]) {
    const result = await task(input);
    assert.deepEqual([result.status, result.valid, result.findings], ['error', null, []], JSON.stringify(input));
  }
  assert.equal(calls.length, 0);
});

test('private, loopback and local targets are blocked before any connection', async () => {
  const { task, calls } = setup();
  for (const url of ['https://127.0.0.1', 'https://10.0.0.5', 'https://[::1]', 'https://169.254.169.254', 'https://localhost', 'https://printer.local', 'https://user:pw@example.com', 'ftp://example.com']) {
    const result = await task({ url });
    assert.deepEqual([result.status, result.valid], ['blocked', null], url);
  }
  assert.equal(calls.length, 0);
});

test('a name that resolves to a private address is blocked (DNS rebinding style)', async () => {
  let connected = false;
  const task = createCertificateTask({ resolver: async () => [{ address: '192.168.1.10', family: 4 }], connect: async () => { connected = true; throw new Error('unreachable'); } });
  const result = await task({ url: 'https://innocent.example.com' });
  assert.equal(result.status, 'blocked');
  assert.equal(connected, false);
});

test('synthetic NAT64 answers are ignored, never connected to, and never let a private target through', async () => {
  const cases: [string, { address: string; family: number }[], string | null][] = [
    ['real IPv4 next to a NAT64 address', [{ address: '64:ff9b::808:808', family: 6 }, { address: '8.8.8.8', family: 4 }], '8.8.8.8'],
    ['NAT64 address that embeds a private IPv4', [{ address: '64:ff9b::7f00:1', family: 6 }, { address: '8.8.8.8', family: 4 }], '8.8.8.8'],
    ['only a NAT64 address', [{ address: '64:ff9b::808:808', family: 6 }], null],
    ['NAT64 address next to a private IPv4', [{ address: '64:ff9b::808:808', family: 6 }, { address: '10.0.0.1', family: 4 }], null],
  ];
  for (const [name, answers, connectedTo] of cases) {
    const targets: string[] = [];
    const task = createCertificateTask({ resolver: async () => answers, now, connect: async (target) => { targets.push(target.address); return { cert: good, authorized: true }; } });
    const result = await task({ url: 'https://example.com' });
    if (connectedTo) assert.deepEqual([result.status, targets], ['ok', [connectedTo]], name);
    else assert.deepEqual([result.status, targets], ['blocked', []], name);
  }
});

test('DNS and connection failures become structured errors, never exceptions', async () => {
  const dns = createCertificateTask({ resolver: async () => { throw Object.assign(new Error('x'), { code: 'ENOTFOUND' }); } });
  assert.deepEqual(await dns({ url: 'https://nope.example.com' }), { status: 'error', valid: null, reason: 'Host could not be resolved', findings: [] });
  const refused = setup(async () => { throw Object.assign(new Error('x'), { code: 'ECONNREFUSED' }); });
  assert.equal((await refused.task({ url: 'https://example.com' })).reason, 'Connection refused');
  const odd = setup(async () => { throw 'not even an Error'; });
  assert.equal((await odd.task({ url: 'https://example.com' })).status, 'error');
});

test('connectTls rejects on a refused connection and on a server that never answers', async () => {
  await assert.rejects(connectTls({ hostname: 'localhost', address: '127.0.0.1', port: 1 }, 2000));
  const sockets = new Set<Socket>();
  const silent = createServer((socket) => { sockets.add(socket); }).listen(0, '127.0.0.1');
  await new Promise((resolve) => silent.once('listening', resolve));
  try {
    const { port } = silent.address() as { port: number };
    await assert.rejects(connectTls({ hostname: 'localhost', address: '127.0.0.1', port }, 300), { code: 'ETIMEDOUT' });
  } finally { for (const socket of sockets) socket.destroy(); silent.close(); }
});

// Real internet. Run with:  $env:LIVE_TLS = '1'; .\node_modules\.bin\tsx.cmd --test test/certificate-task.test.ts
test('live sites', { skip: !process.env.LIVE_TLS }, async () => {
  const expected: Record<string, string | null> = {
    'https://github.com': null,
    'https://expired.badssl.com': 'cert.expired',
    'https://self-signed.badssl.com': 'cert.self_signed',
    'https://wrong.host.badssl.com': 'cert.hostname_mismatch',
    'https://untrusted-root.badssl.com': 'cert.untrusted_chain',
    'https://incomplete-chain.badssl.com': 'cert.untrusted_chain',
  };
  for (const [url, finding] of Object.entries(expected)) {
    const result = await validateCertificate({ url });
    assert.equal(result.status, 'ok', `${url}: ${result.reason}`);
    if (finding) assert.ok(result.findings.some((f) => f.id === finding), `${url}: ${JSON.stringify(result.findings)}`);
    else assert.equal(result.valid, true, url);
  }
});