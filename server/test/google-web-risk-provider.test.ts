import assert from 'node:assert/strict';
import test from 'node:test';
import { BlacklistModule, createBlacklistChecker, createGoogleWebRiskProvider } from '../src/modules/threat-detection/index.js';
import type { GoogleWebRiskProviderOptions } from '../src/modules/threat-detection/index.js';

const input = 'https://example.com/Path?token=sensitive&next=a+b';
const apiKey = 'server-secret-key';
const context = () => ({ signal: new AbortController().signal });
const match = { threat: { threatTypes: ['SOCIAL_ENGINEERING'], expireTime: '2030-01-01T00:00:00.123456789Z' } };
const providerFor = (payload: unknown) => createGoogleWebRiskProvider({ apiKey,
  fetch: async () => Response.json(payload) });

test('public Google Web Risk provider performs encoded GET lookup with header key and all three threat lists', async () => {
  const signal = new AbortController().signal;
  let calls = 0;
  const provider = createGoogleWebRiskProvider({ apiKey, fetch: async (endpoint, init) => {
    calls++;
    const url = new URL(String(endpoint));
    assert.equal(url.origin, 'https://webrisk.googleapis.com');
    assert.equal(url.pathname, '/v1/uris:search');
    assert.equal(url.searchParams.get('uri'), input);
    assert.equal(url.searchParams.has('key'), false);
    assert.ok(!String(endpoint).includes(apiKey));
    assert.deepEqual(url.searchParams.getAll('threatTypes'), ['SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE']);
    assert.equal(init?.method, 'GET');
    assert.equal(init?.body, undefined);
    assert.equal(init?.redirect, 'error');
    assert.equal(init?.signal, signal);
    assert.equal(new Headers(init.headers).get('x-goog-api-key'), apiKey);
    return Response.json(match);
  } });
  assert.equal(provider.name, 'google-web-risk');
  assert.deepEqual(await provider.check('https://EXAMPLE.com.:443/Path?token=sensitive&next=a+b#fragment', { signal }),
    { matched: true, details: 'Google Web Risk match: SOCIAL_ENGINEERING' });
  assert.equal(calls, 1);
});

test('documented empty response is a completed negative; validated threat enums are deduplicated', async () => {
  assert.deepEqual(await providerFor({}).check(input, context()), { matched: false });
  for (const type of ['SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE']) {
    const provider = providerFor({ threat: { ...match.threat, threatTypes: [type, type] }, privateMetadata: input });
    assert.deepEqual(await provider.check(input, context()), { matched: true, details: `Google Web Risk match: ${type}` });
  }
});

test('malformed or error payloads fail inconclusively instead of masquerading as negative checks', async () => {
  for (const payload of [null, [], false, '', { error: { message: `${apiKey} ${input}` } },
    { ...match, error: { message: 'unexpected error envelope' } }, { unexpected: true },
    { threat: null }, { threat: {} }, { threat: { ...match.threat, threatTypes: [] } },
    { threat: { ...match.threat, threatTypes: ['THREAT_TYPE_UNSPECIFIED'] } },
    { threat: { ...match.threat, threatTypes: ['SOCIAL_ENGINEERING', 'injected text'] } },
    { threat: { ...match.threat, threatTypes: 'MALWARE' } },
    { threat: { ...match.threat, expireTime: undefined } },
    { threat: { ...match.threat, expireTime: 'not a timestamp' } }]) {
    await assert.rejects(providerFor(payload).check(input, context()), {
      message: 'Google Web Risk returned an invalid provider response',
    });
  }
});

test('HTTP auth/quota/network/JSON errors expose no provider bodies, keys, URLs, or raw causes', async () => {
  const fetchers: Array<typeof globalThis.fetch> = [
    ...[400, 401, 403, 429, 500].map((status): typeof globalThis.fetch =>
      async () => new Response(`${apiKey} ${input}`, { status })),
    async () => { throw new Error(`${apiKey} ${input}`); },
    async () => new Response('not-json'),
  ];
  for (const fetch of fetchers) {
    const module = new BlacklistModule({ providers: [createGoogleWebRiskProvider({ apiKey, fetch })] });
    const result = await module.analyze(input);
    assert.equal(result.status, 'error');
    assert.equal(result.details.status, 'unknown');
    assert.equal(result.details.errors[0]?.code, 'provider_error');
    assert.deepEqual(result.evidence, []);
    const diagnostics = JSON.stringify({ errors: result.details.errors, issues: result.issues });
    assert.ok(!diagnostics.includes(apiKey));
    assert.ok(!diagnostics.includes(input));
  }
});

test('invalid inputs and pre-aborted requests cannot invoke Google', async () => {
  let calls = 0;
  const provider = createGoogleWebRiskProvider({ apiKey, fetch: async () => { calls++; return Response.json({}); } });
  for (const url of ['/login', 'javascript:alert(1)', 'https://user:secret@example.com/', 'https:example.com']) {
    await assert.rejects(provider.check(url, context()));
  }
  const controller = new AbortController();
  controller.abort(new Error('secret abort reason'));
  await assert.rejects(provider.check(input, { signal: controller.signal }), { message: 'Google Web Risk request aborted' });
  assert.equal(calls, 0);
});

test('checker bounds non-cooperative Google requests, forwards abort, and preserves snapshot matches', async () => {
  let signal: AbortSignal | undefined;
  const provider = createGoogleWebRiskProvider({ apiKey, fetch: async (_endpoint, init) => {
    signal = init?.signal ?? undefined;
    return new Promise<Response>(() => {});
  } });
  const result = await createBlacklistChecker({ providers: [provider], timeoutMs: 10,
    snapshots: [{ source: 'local', updatedAt: '2026-01-01T00:00:00Z', domains: ['example.com'] }],
  })(input);
  assert.equal(result.status, 'matched');
  assert.equal(result.errors[0]?.code, 'timeout');
  assert.equal(signal?.aborted, true);
});

test('provider snapshots options and requires an explicit nonempty API key', async () => {
  const options: GoogleWebRiskProviderOptions = { apiKey, fetch: async (_endpoint, init) => {
    assert.equal(new Headers(init?.headers).get('x-goog-api-key'), apiKey);
    return Response.json({});
  } };
  const provider = createGoogleWebRiskProvider(options);
  options.apiKey = 'changed';
  options.fetch = async () => { throw new Error('Must not use changed fetch'); };
  assert.deepEqual(await provider.check(input, context()), { matched: false });
  for (const key of [undefined, null, '', ' ', 'key\nvalue', 'key\tvalue', 12]) {
    assert.throws(() => createGoogleWebRiskProvider({ apiKey: key as string }), /API key/);
  }
});
