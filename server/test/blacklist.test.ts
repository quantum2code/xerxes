import assert from 'node:assert/strict';
import test from 'node:test';
import { createBlacklistChecker } from '../src/modules/threat-detection/blacklist/index.js';
import type {
  BlacklistOptions,
  BlacklistProvider,
  BlacklistSnapshot,
} from '../src/modules/threat-detection/blacklist/index.js';

const updatedAt = '2026-01-02T03:04:05.000Z';
const snapshot = (domains: string[]): BlacklistSnapshot => ({ source: 'local', updatedAt, domains });

// All providers below are in-memory stubs; these tests never fetch feeds or contact services.
test('domain matching respects exact hosts and subdomain label boundaries', async () => {
  const check = createBlacklistChecker({ snapshots: [snapshot(['ExAmPlE.CoM.'])] });
  for (const host of ['example.com', 'EXAMPLE.COM.', 'a.example.com', 'a.b.example.com']) {
    const result = await check(`https://${host}/anything?x=1`);
    assert.equal(result.status, 'matched', host);
    assert.deepEqual(result.matches, [{ source: 'local', kind: 'snapshot' }]);
    assert.deepEqual(result.checkedSources, [{ source: 'local', kind: 'snapshot' }]);
    assert.deepEqual(result.snapshots, [{ source: 'local', updatedAt }]);
    assert.deepEqual(result.errors, []);
  }
  for (const host of ['notexample.com', 'example.com.evil.org', 'example.net', 'examplecom.org']) {
    assert.equal((await check(`https://${host}/example.com`)).status, 'no_match', host);
  }
});

test('URL keys ignore hashes, normalize hosts/default ports, but retain path and query', async () => {
  const check = createBlacklistChecker({ snapshots: [{
    source: 'urls', updatedAt, urls: ['https://EXAMPLE.com.:443/Case?a=1&b=2#original'],
  }] });
  assert.equal((await check('https://example.com/Case?a=1&b=2#other')).status, 'matched');
  for (const url of [
    'https://example.com/case?a=1&b=2', 'https://example.com/Case?b=2&a=1',
    'https://example.com/Case?a=1', 'http://example.com/Case?a=1&b=2',
    'https://sub.example.com/Case?a=1&b=2', 'https://example.com/Case/extra?a=1&b=2',
  ]) assert.equal((await check(url)).status, 'no_match', url);
});

test('normalizes IDNs and accepts registrable hosts beneath private suffixes', async () => {
  const check = createBlacklistChecker({ snapshots: [snapshot(['BÜCHER.de.', 'project.github.io'])] });
  for (const host of ['bücher.de', 'xn--bcher-kva.de', 'shop.bücher.de', 'project.github.io', 'a.project.github.io']) {
    assert.equal((await check(`https://${host}/`)).status, 'matched', host);
  }
  assert.equal((await check('https://other.github.io/')).status, 'no_match');
});

test('rejects bare public/private suffixes and malformed domain-only entries', () => {
  for (const domain of [
    'com', 'COM.', 'co.uk', 'github.io', 'blogspot.com', 'localhost', '', ' example.com',
    '*.example.com', 'example.com/path', 'example.com:443', 'user@example.com',
    'https://example.com', '//example.com', 'example.com?x=1', 'example.com#hash',
    'example.com\\path', 'example..com', 'example.com..', '-bad.com', 'bad-.com',
    'bad_name.com', 'bad\n.com', 'bad\u007f.com', 'example%2ecom', '999.999.999.999',
    '127.1', `${'a'.repeat(64)}.com`,
  ]) {
    assert.throws(() => createBlacklistChecker({ snapshots: [snapshot([domain])] }), TypeError, domain);
  }
});

test('IP host entries match only the address, with IPv6 canonicalization', async () => {
  const check = createBlacklistChecker({ snapshots: [snapshot(['192.0.2.1', '2001:0db8:0:0:0:0:0:1'])] });
  assert.equal((await check('https://192.0.2.1/')).status, 'matched');
  assert.equal((await check('https://[2001:db8::1]/')).status, 'matched');
  assert.equal((await check('https://a.192.0.2.1.example.org/')).status, 'no_match');
  assert.equal((await check('https://192.0.2.10/')).status, 'no_match');
});

test('providers receive canonical full URLs and their matches preserve optional details', async () => {
  const calls: string[] = [];
  const check = createBlacklistChecker({ providers: [{
    name: 'remote',
    check: async (url, { signal }) => {
      calls.push(url);
      assert.ok(signal instanceof AbortSignal);
      assert.equal(signal.aborted, false);
      return { matched: true, details: 'listed by test provider' };
    },
  }, { name: 'clean', check: async () => ({ matched: false, details: 'not a match' }) }] });
  const result = await check('https://EXAMPLE.com.:443/Path?token=sensitive#private');
  assert.deepEqual(calls, ['https://example.com/Path?token=sensitive']);
  assert.equal(result.status, 'matched');
  assert.deepEqual(result.matches, [{ source: 'remote', kind: 'provider', details: 'listed by test provider' }]);
  assert.deepEqual(result.checkedSources, [
    { source: 'remote', kind: 'provider' }, { source: 'clean', kind: 'provider' },
  ]);
  assert.deepEqual(result.snapshots, []);
  assert.deepEqual(result.errors, []);
});

test('timeout bounds even non-cooperative providers, aborts signals, and preserves partial matches', { timeout: 2000 }, async () => {
  let timedSignal: AbortSignal | undefined;
  let lateReject: ((reason: Error) => void) | undefined;
  const check = createBlacklistChecker({
    timeoutMs: 20,
    snapshots: [snapshot(['example.com'])],
    providers: [
      { name: 'slow', check: (_url, { signal }) => {
        timedSignal = signal;
        return new Promise((_resolve, reject) => { lateReject = reject; });
      } },
      { name: 'broken', check: async () => { throw new Error('service unavailable'); } },
      { name: 'listed', check: async () => ({ matched: true }) },
    ],
  });
  const result = await check('https://example.com/');
  assert.equal(result.status, 'matched');
  assert.equal(timedSignal?.aborted, true);
  assert.deepEqual(result.matches, [
    { source: 'local', kind: 'snapshot' }, { source: 'listed', kind: 'provider' },
  ]);
  assert.deepEqual(result.errors.map(({ source, kind, code }) => ({ source, kind, code })), [
    { source: 'slow', kind: 'provider', code: 'timeout' },
    { source: 'broken', kind: 'provider', code: 'provider_error' },
  ]);
  assert.match(result.errors[0]!.message, /20 ms/);
  assert.equal(result.errors[1]!.message, 'service unavailable');
  assert.equal(result.checkedSources.length, 4);
  lateReject!(new Error('late failure must be consumed'));
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(result.errors.length, 2);
});

test('a local match survives provider failure without any provider match', async () => {
  const check = createBlacklistChecker({ snapshots: [snapshot(['example.com'])], providers: [
    { name: 'offline', check: async () => { throw new Error('offline'); } },
  ] });
  const result = await check('https://example.com');
  assert.equal(result.status, 'matched');
  assert.deepEqual(result.matches, [{ source: 'local', kind: 'snapshot' }]);
  assert.equal(result.errors.length, 1);
});

test('failures, synchronous throws, malformed provider results, and timeouts yield unknown without a match', async () => {
  const checks: BlacklistProvider['check'][] = [
    async () => { throw new Error('failed'); },
    () => { throw 'synchronous failure'; },
    async () => ({ matched: 'yes' } as unknown as { matched: boolean }),
    async () => ({ matched: false, details: 1 } as unknown as { matched: boolean }),
    async () => null as unknown as { matched: boolean },
    () => new Promise(() => {}),
  ];
  for (const providerCheck of checks) {
    const check = createBlacklistChecker({
      timeoutMs: 5,
      snapshots: [snapshot([])],
      providers: [
        { name: 'failing', check: providerCheck },
        { name: 'clean', check: async () => ({ matched: false }) },
      ],
    });
    const result = await check('https://example.com/');
    assert.equal(result.status, 'unknown');
    assert.deepEqual(result.matches, []);
    assert.equal(result.errors.length, 1);
    assert.equal(result.checkedSources.length, 3);
  }
});

test('no sources is unknown; completed negative checks are no_match', async () => {
  for (const options of [undefined, {}, { snapshots: [], providers: [] }]) {
    assert.deepEqual(await createBlacklistChecker(options)('https://example.com/'), {
      status: 'unknown', matches: [], checkedSources: [], errors: [], snapshots: [],
    });
  }
  for (const options of [
    { snapshots: [snapshot([])] },
    { providers: [{ name: 'clean', check: async () => ({ matched: false }) }] },
  ]) assert.equal((await createBlacklistChecker(options)('https://example.com/')).status, 'no_match');
});

test('creation clones configuration and every concurrent call returns independent state', async () => {
  const local = { source: 'original', updatedAt, urls: ['https://example.com/A#hash'], domains: ['bücher.de'] };
  const provider = { name: 'original-provider', check: async () => ({ matched: false }) };
  const options = { timeoutMs: 5000, snapshots: [local], providers: [provider] };
  const check = createBlacklistChecker(options);
  local.source = 'changed';
  local.updatedAt = 'invalid';
  local.urls[0] = 'https://other.org/';
  local.domains[0] = 'other.org';
  provider.name = 'changed';
  provider.check = async () => ({ matched: true });
  options.timeoutMs = 0;
  options.snapshots.length = 0;
  options.providers.length = 0;
  const [a, b, c] = await Promise.all([
    check('https://example.com/A'), check('https://bücher.de/'), check('https://other.org/'),
  ]);
  assert.equal(a.status, 'matched');
  assert.equal(b.status, 'matched');
  assert.equal(c.status, 'no_match');
  assert.deepEqual(a.checkedSources, [
    { source: 'original', kind: 'snapshot' }, { source: 'original-provider', kind: 'provider' },
  ]);
  a.matches[0]!.source = 'mutated';
  a.checkedSources.length = 0;
  a.snapshots[0]!.updatedAt = 'mutated';
  a.errors.push({ source: 'mutated', kind: 'provider', code: 'timeout', message: 'mutated' });
  assert.equal(b.matches[0]!.source, 'original');
  const next = await check('https://example.com/A');
  assert.equal(next.matches[0]!.source, 'original');
  assert.equal(next.snapshots[0]!.updatedAt, updatedAt);
  assert.deepEqual(next.errors, []);
});

test('invalid URL input and credentials reject before providers are invoked', async () => {
  let calls = 0;
  const check = createBlacklistChecker({ providers: [{ name: 'never', check: async () => {
    calls++;
    return { matched: false };
  } }] });
  for (const input of [
    '', 'not a url', '/relative', 'ftp://example.com', 'https://', ' https://example.com',
    'https://example.com/with space', 'https://example.com/\n',
    'https://user:secret@example.com', 'https://user@example.com', 'https://:secret@example.com',
    `https://example.com/${'x'.repeat(8192)}`, null, undefined, 42,
  ]) await assert.rejects(check(input as string), TypeError);
  assert.equal(calls, 0);
  await assert.rejects(createBlacklistChecker()('https://user:secret@example.com'), TypeError);
});

test('invalid configuration throws at creation, including snapshot URLs and calendar dates', () => {
  const invalid: unknown[] = [
    null, [], { timeoutMs: null }, { snapshots: null }, { providers: {} },
    ...[-1, 0, 120001, 1.5, NaN, Infinity, '5'].map((timeoutMs) => ({ timeoutMs })),
    { snapshots: [null] }, { snapshots: [{ source: '', updatedAt }] },
    { snapshots: [{ source: 'local', updatedAt: 'yesterday' }] },
    ...['2026-02-30T00:00:00Z', '2026-01-02', '2026-01-02T03:04:05'].map((date) => ({
      snapshots: [{ source: 'local', updatedAt: date }],
    })),
    { snapshots: [{ source: 'local', updatedAt, urls: 'https://example.com' }] },
    { snapshots: [{ source: 'local', updatedAt, domains: null }] },
    ...['bad-url', 'ftp://example.com', 'https://user:secret@example.com', 1].map((url) => ({
      snapshots: [{ source: 'local', updatedAt, urls: [url] }],
    })),
    { providers: [null] }, { providers: [{ name: '', check: async () => ({ matched: false }) }] },
    { providers: [{ name: 'bad', check: 'not a function' }] },
  ];
  for (const options of invalid) {
    assert.throws(() => createBlacklistChecker(options as BlacklistOptions), TypeError);
  }
  for (const timeoutMs of [1, 120000]) assert.doesNotThrow(() => createBlacklistChecker({ timeoutMs }));
  assert.doesNotThrow(() => createBlacklistChecker({ snapshots: [{
    source: 'local', updatedAt: '2024-02-29T12:30:00+02:00',
  }] }));
});
