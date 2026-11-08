import assert from 'node:assert/strict';
import test from 'node:test';
import {
  BlacklistModule, createBlacklistChecker, createPhishTankProvider,
} from '../src/modules/threat-detection/index.js';
import type { PhishTankProviderOptions } from '../src/modules/threat-detection/index.js';

const url = 'https://example.com/Path?token=sensitive&next=a+b';
const apiKey = 'private-api-key';
const context = () => ({ signal: new AbortController().signal });
const jsonFetch = (payload: unknown): typeof globalThis.fetch => async () => Response.json(payload);
const providerFor = (payload: unknown) => createPhishTankProvider({ fetch: jsonFetch(payload) });

// All HTTP responses are local fixtures; no test contacts PhishTank.
test('PhishTank posts encoded canonical URLs, explicit keys, headers, and the caller signal', async () => {
  const controller = new AbortController();
  let calls = 0;
  const provider = createPhishTankProvider({
    apiKey: 'key+with&reserved=characters',
    userAgent: 'phishtank/test application',
    fetch: async (endpoint, init) => {
      calls++;
      assert.equal(endpoint, 'https://checkurl.phishtank.com/checkurl/');
      assert.equal(init?.method, 'POST');
      assert.equal(init?.redirect, 'error');
      assert.equal(init?.signal, controller.signal);
      const headers = new Headers(init?.headers);
      assert.equal(headers.get('accept'), 'application/json');
      assert.equal(headers.get('content-type'), 'application/x-www-form-urlencoded');
      assert.equal(headers.get('user-agent'), 'phishtank/test application');
      assert.ok(init?.body instanceof URLSearchParams);
      assert.deepEqual([...init.body], [
        ['url', url], ['format', 'json'], ['app_key', 'key+with&reserved=characters'],
      ]);
      assert.equal(init.body.toString(),
        'url=https%3A%2F%2Fexample.com%2FPath%3Ftoken%3Dsensitive%26next%3Da%2Bb&format=json&app_key=key%2Bwith%26reserved%3Dcharacters');
      return Response.json({ results: { in_database: true, verified: 'y', valid: 'y' } });
    },
  });
  assert.equal(provider.name, 'phishtank');
  assert.deepEqual(await provider.check('https://EXAMPLE.com.:443/Path?token=sensitive&next=a+b#private', {
    signal: controller.signal,
  }), { matched: true, details: 'Verified phishing URL in PhishTank' });
  assert.equal(calls, 1);
});

test('PhishTank keyless requests omit app_key and use the descriptive default user-agent', async () => {
  const provider = createPhishTankProvider({ fetch: async (_endpoint, init) => {
    assert.ok(init?.body instanceof URLSearchParams);
    assert.equal(init.body.has('app_key'), false);
    assert.equal(new Headers(init.headers).get('user-agent'), 'phishtank/xerxes');
    return Response.json({ results: { in_database: false } });
  } });
  assert.deepEqual(await provider.check(url, context()), { matched: false });
});

test('PhishTank accepts only explicit boolean or y/n verification flags', async () => {
  for (const verified of [true, 'y']) {
    for (const valid of [true, 'y']) {
      const provider = providerFor({ results: {
        in_database: true, verified, valid, url, phish_detail_page: url, message: apiKey,
      } });
      assert.deepEqual(await provider.check(url, context()), {
        matched: true, details: 'Verified phishing URL in PhishTank',
      });
    }
    for (const valid of [false, 'n']) {
      assert.deepEqual(await providerFor({ results: {
        in_database: true, verified, valid,
      } }).check(url, context()), { matched: false });
    }
  }
  assert.deepEqual(await providerFor({ results: { in_database: false } }).check(url, context()), {
    matched: false,
  });
});

test('PhishTank rejects unverified entries rather than declaring them clean', async () => {
  for (const verified of [false, 'n']) {
    for (const valid of [true, false, 'y', 'n']) {
      const provider = providerFor({ results: { in_database: true, verified, valid } });
      await assert.rejects(provider.check(url, context()), /PhishTank.*incomplete or unverified/);
    }
  }
  const result = await createBlacklistChecker({ providers: [providerFor({ results: {
    in_database: true, verified: 'n', valid: 'y', message: `${url} ${apiKey}`,
  } })] })(url);
  assert.equal(result.status, 'unknown');
  assert.deepEqual(result.matches, []);
  assert.equal(result.errors[0]?.code, 'provider_error');
  assert.equal(result.errors[0]?.message, 'PhishTank returned an incomplete or unverified provider response');
});

test('PhishTank rejects malformed payloads with a generic sanitized response error', async () => {
  const payloads: unknown[] = [
    null, [], {}, { results: null }, { results: [] }, { results: {} },
    { error: `${url} ${apiKey}` },
    ...['true', 'false', 'y', 'n', 1, 0, null].map((in_database) => ({ results: { in_database } })),
    { results: { in_database: true } },
    { results: { in_database: true, verified: true } },
    { results: { in_database: true, valid: true } },
  ];
  for (const flag of ['true', 'false', 'yes', 'no', 'Y', 'N', '', 1, 0, null, {}, [], url, apiKey]) {
    payloads.push({ results: { in_database: true, verified: flag, valid: true } });
    payloads.push({ results: { in_database: true, verified: true, valid: flag } });
  }
  for (const payload of payloads) {
    await assert.rejects(providerFor(payload).check(url, context()), {
      name: 'Error', message: 'PhishTank returned an invalid provider response',
    });
  }
});

test('PhishTank HTTP failures expose only sanitized status and provider information', async () => {
  for (const status of [401, 403, 429, 509, 302, 400, 500, 503]) {
    const provider = createPhishTankProvider({ apiKey, fetch: async () => new Response(
      `${url} ${apiKey} sensitive service message`, { status, statusText: apiKey },
    ) });
    let message = `PhishTank request failed (HTTP ${status})`;
    if (status === 401 || status === 403) {
      message = `PhishTank authentication or access denied (HTTP ${status})`;
    }
    if (status === 429 || status === 509) message = `PhishTank rate limit exceeded (HTTP ${status})`;
    await assert.rejects(provider.check(url, context()), { name: 'Error', message });
  }
});

test('PhishTank sanitizes fetch and JSON failures without leaking sensitive causes', async () => {
  const fetchFailure = createPhishTankProvider({ apiKey, fetch: async () => {
    throw new Error(`${url} ${apiKey}`, { cause: new Error(apiKey) });
  } });
  await assert.rejects(fetchFailure.check(url, context()), (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.equal(error.message, 'PhishTank request failed');
    assert.equal(error.cause, undefined);
    assert.equal(error.stack?.includes(apiKey), false);
    assert.equal(error.stack?.includes(url), false);
    return true;
  });
  const invalidJson = createPhishTankProvider({ apiKey, fetch: async () => new Response(`${url} ${apiKey}`) });
  await assert.rejects(invalidJson.check(url, context()), {
    name: 'Error', message: 'PhishTank returned invalid JSON',
  });
});

test('PhishTank rejects invalid URLs and credential-bearing inputs before fetching', async () => {
  let calls = 0;
  const provider = createPhishTankProvider({ fetch: async () => {
    calls++;
    return Response.json({ results: { in_database: false } });
  } });
  for (const input of ['', 'invalid', 'ftp://example.com', 'https://user:secret@example.com',
    'https://user@example.com', 'https://:secret@example.com']) {
    await assert.rejects(provider.check(input, context()), TypeError);
  }
  assert.equal(calls, 0);
});

test('PhishTank checks pre-aborted signals without fetching or echoing abort reasons', async () => {
  let calls = 0;
  const provider = createPhishTankProvider({ fetch: async () => {
    calls++;
    return Response.json({ results: { in_database: false } });
  } });
  const controller = new AbortController();
  controller.abort(new Error(`${url} ${apiKey}`));
  await assert.rejects(provider.check(url, { signal: controller.signal }), {
    name: 'Error', message: 'PhishTank request aborted',
  });
  assert.equal(calls, 0);
});

test('PhishTank forwards in-flight abort and checker deadlines produce unknown', { timeout: 2000 }, async () => {
  let requestSignal: AbortSignal | null | undefined;
  let aborts = 0;
  const provider = createPhishTankProvider({ fetch: async (_endpoint, init) => {
    requestSignal = init?.signal;
    return new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => {
        aborts++;
        reject(new Error(`${url} ${apiKey}`));
      }, { once: true });
    });
  } });
  const controller = new AbortController();
  const pending = provider.check(url, { signal: controller.signal });
  assert.equal(requestSignal, controller.signal);
  controller.abort();
  await assert.rejects(pending, { name: 'Error', message: 'PhishTank request failed' });
  const result = await createBlacklistChecker({ timeoutMs: 10, providers: [provider] })(url);
  assert.equal(result.status, 'unknown');
  assert.equal(result.errors[0]?.code, 'timeout');
  assert.equal(requestSignal?.aborted, true);
  assert.equal(aborts, 2);
});

test('PhishTank captures configuration at creation', async () => {
  let calls = 0;
  const options: PhishTankProviderOptions = { apiKey, userAgent: 'phishtank/original', fetch: async (_endpoint, init) => {
    calls++;
    assert.ok(init?.body instanceof URLSearchParams);
    assert.equal(init.body.get('app_key'), apiKey);
    assert.equal(new Headers(init.headers).get('user-agent'), 'phishtank/original');
    return Response.json({ results: { in_database: false } });
  } };
  const provider = createPhishTankProvider(options);
  options.apiKey = 'changed';
  options.userAgent = 'phishtank/changed';
  options.fetch = async () => { throw new Error('must not use mutated fetch'); };
  await provider.check(url, context());
  await provider.check(url, context());
  assert.equal(calls, 2);
});

test('PhishTank validates explicit API keys and printable nonblank user-agents at creation', () => {
  for (const invalid of ['', ' ', '\t', 'bad key', 'bad\nkey', 'bad\rkey', 'bad\u0000key', 'bad\u007fkey', null, 42]) {
    assert.throws(() => createPhishTankProvider({ apiKey: invalid as string }), TypeError);
  }
  for (const invalid of ['', ' ', '   ', '\t', 'agent\r\nheader', 'agent\u0000', 'agent\u007f', 'agent\u0085', 'café', null, 42]) {
    assert.throws(() => createPhishTankProvider({ userAgent: invalid as string }), TypeError);
  }
  for (const userAgent of ['phishtank/test', 'Xerxes application (security contact)', ' agent ']) {
    assert.doesNotThrow(() => createPhishTankProvider({ userAgent, fetch: jsonFetch({}) }));
  }
  assert.doesNotThrow(() => createPhishTankProvider());
});

test('BlacklistModule returns PhishTank matches as factual evidence without sensitive URL data', async () => {
  let calls = 0;
  const provider = createPhishTankProvider({ apiKey, fetch: async (_endpoint, init) => {
    calls++;
    assert.ok(init?.body instanceof URLSearchParams);
    assert.equal(init.body.get('url'), url);
    return Response.json({ results: { in_database: true, verified: 'y', valid: 'y' } });
  } });
  const result = await new BlacklistModule({ providers: [provider] })
    .analyze('https://EXAMPLE.com.:443/Path?token=sensitive&next=a+b#private');
  assert.equal(calls, 1);
  assert.equal(result.module, 'blacklistCheck');
  assert.equal(result.status, 'completed');
  assert.deepEqual(result.evidence, [{
    module: 'blacklistCheck', hostname: 'example.com', target: 'submitted',
    code: 'BLACKLIST_MATCH', source: 'phishtank', sourceKind: 'provider',
  }]);
  assert.equal(result.details.status, 'matched');
  assert.deepEqual(result.details.matches, [{
    source: 'phishtank', kind: 'provider', details: 'Verified phishing URL in PhishTank',
  }]);
  assert.deepEqual(result.details.checkedSources, [{ source: 'phishtank', kind: 'provider' }]);
  assert.deepEqual(result.details.errors, []);
  assert.deepEqual(result.issues, []);
  assert.equal(JSON.stringify(result).includes('sensitive'), false);
  assert.equal(JSON.stringify(result).includes(apiKey), false);
});

test('BlacklistModule completes negative PhishTank checks without inventing evidence', async () => {
  for (const results of [
    { in_database: false },
    { in_database: true, verified: 'y', valid: 'n' },
  ]) {
    const result = await new BlacklistModule({ providers: [providerFor({ results })] }).analyze(url);
    assert.equal(result.status, 'completed');
    assert.equal(result.details.status, 'no_match');
    assert.deepEqual(result.evidence, []);
    assert.deepEqual(result.details.matches, []);
    assert.deepEqual(result.details.errors, []);
    assert.deepEqual(result.issues, []);
  }
});

test('BlacklistModule reports unavailable or unverified PhishTank checks as errors, not clean results', async () => {
  const fetches: (typeof globalThis.fetch)[] = [
    jsonFetch({ results: { in_database: true, verified: 'n', valid: 'y' } }),
    jsonFetch({ error: `${url} ${apiKey}` }),
    async () => new Response(`${url} ${apiKey}`, { status: 429 }),
    async () => new Response(`${url} ${apiKey}`),
  ];
  for (const fetch of fetches) {
    const provider = createPhishTankProvider({ apiKey, fetch });
    const result = await new BlacklistModule({ providers: [provider] }).analyze(url);
    assert.equal(result.status, 'error');
    assert.equal(result.details.status, 'unknown');
    assert.deepEqual(result.evidence, []);
    assert.equal(result.details.errors[0]?.source, 'phishtank');
    assert.equal(result.details.errors[0]?.code, 'provider_error');
    assert.deepEqual(result.issues, ['phishtank: provider_error']);
    assert.equal(JSON.stringify(result).includes('sensitive'), false);
    assert.equal(JSON.stringify(result).includes(apiKey), false);
  }
});

test('BlacklistModule preserves snapshot matches when PhishTank is unavailable', async () => {
  const provider = createPhishTankProvider({ fetch: async () => new Response(null, { status: 503 }) });
  const result = await new BlacklistModule({
    providers: [provider],
    snapshots: [{ source: 'local', updatedAt: '2026-01-02T03:04:05Z', domains: ['example.com'] }],
  }).analyze(url);
  assert.equal(result.status, 'partial');
  assert.equal(result.details.status, 'matched');
  assert.deepEqual(result.details.matches, [{ source: 'local', kind: 'snapshot' }]);
  assert.deepEqual(result.evidence, [{
    module: 'blacklistCheck', hostname: 'example.com', target: 'submitted',
    code: 'BLACKLIST_MATCH', source: 'local', sourceKind: 'snapshot',
  }]);
  assert.deepEqual(result.issues, ['phishtank: provider_error']);
});

test('BlacklistModule bounds PhishTank requests and reports deadline failures', { timeout: 2000 }, async () => {
  let requestSignal: AbortSignal | null | undefined;
  const provider = createPhishTankProvider({ fetch: async (_endpoint, init) => {
    requestSignal = init?.signal;
    return new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new Error('Request cancelled')), { once: true });
    });
  } });
  const result = await new BlacklistModule({ providers: [provider], timeoutMs: 10 }).analyze(url);
  assert.equal(requestSignal?.aborted, true);
  assert.equal(result.status, 'error');
  assert.equal(result.details.status, 'unknown');
  assert.deepEqual(result.evidence, []);
  assert.equal(result.details.errors[0]?.code, 'timeout');
  assert.deepEqual(result.issues, ['phishtank: timeout']);
});
