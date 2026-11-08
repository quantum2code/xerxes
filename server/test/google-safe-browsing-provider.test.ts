import assert from 'node:assert/strict';
import test from 'node:test';
import { BlacklistModule, createBlacklistChecker, createGoogleSafeBrowsingProvider, GOOGLE_SAFE_BROWSING_ADVISORY,
  MlPhishingModule } from '../src/modules/threat-detection/index.js';
import { createServerPipelineOptions } from '../src/server-options.js';

const input = 'https://example.com/Path?token=sensitive&next=a+b';
const apiKey = 'private-key';
const context = () => ({ signal: new AbortController().signal });
const match = { threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM', threatEntryType: 'URL',
  threat: { url: input }, cacheDuration: '300.123456789s' };
const providerFor = (payload: unknown) => createGoogleSafeBrowsingProvider({ apiKey,
  fetch: async () => Response.json(payload) });

test('Safe Browsing POSTs one canonical URL and valid list selectors, with key only in a header', async () => {
  const signal = new AbortController().signal;
  let calls = 0;
  const provider = createGoogleSafeBrowsingProvider({ apiKey, fetch: async (endpoint, init) => {
    calls++;
    assert.equal(endpoint, 'https://safebrowsing.googleapis.com/v4/threatMatches:find');
    assert.equal(init?.method, 'POST');
    assert.equal(init?.redirect, 'error');
    assert.equal(init?.signal, signal);
    assert.equal(new Headers(init.headers).get('x-goog-api-key'), apiKey);
    assert.equal(new Headers(init.headers).get('content-type'), 'application/json');
    assert.deepEqual(JSON.parse(String(init.body)), {
      client: { clientId: 'xerxes', clientVersion: '1.0.0' },
      threatInfo: { threatTypes: ['SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE'],
        platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url: input }] },
    });
    return Response.json({ matches: [match] });
  } });
  const result = await provider.check('https://EXAMPLE.com.:443/Path?token=sensitive&next=a+b#private', { signal });
  assert.equal(provider.name, 'google-safe-browsing');
  assert.equal(result.matched, true);
  assert.match(result.details!, /Potentially unsafe/);
  assert.ok(result.details!.includes(GOOGLE_SAFE_BROWSING_ADVISORY));
  assert.ok(!result.details!.includes('sensitive'));
  assert.equal(calls, 1);
});

test('negative lookups contain no Google advisory; matches are validated and deduplicated', async () => {
  for (const payload of [{}, { matches: [] }]) {
    assert.deepEqual(await providerFor(payload).check(input, context()), { matched: false });
  }
  const result = await providerFor({ matches: [match, match, { ...match, threatType: 'MALWARE', platformType: 'WINDOWS' }] })
    .check(input, context());
  assert.match(result.details!, /SOCIAL_ENGINEERING, MALWARE/);
  assert.equal(result.details!.split('Advisory provided by Google').length, 2);
});

test('malformed/error/mismatched responses are inconclusive, not clean or incorrect matches', async () => {
  for (const payload of [null, [], false, '', { error: { message: apiKey } }, { unknown: true },
    { matches: null }, { matches: {} }, { matches: [null] }, { matches: [{ ...match, threatType: 'UNKNOWN' }] },
    { matches: [{ ...match, platformType: 'UNKNOWN' }] }, { matches: [{ ...match, threatEntryType: 'EXECUTABLE' }] },
    { matches: [{ ...match, threat: { url: 'https://unrelated.example/' } }] },
    { matches: [{ ...match, threat: { url: 'https://user:secret@example.com/' } }] },
    { matches: [{ ...match, cacheDuration: 'forever' }] }, { matches: [{ ...match, cacheDuration: '-1s' }] },
    { matches: [match], error: { message: 'bad envelope' } }]) {
    await assert.rejects(providerFor(payload).check(input, context()), {
      message: 'Google Safe Browsing returned an invalid provider response',
    });
  }
});

test('Google errors, invalid JSON, network errors, and quota failures have sanitized inconclusive results', async () => {
  const fetchers: Array<typeof globalThis.fetch> = [
    ...[400, 401, 403, 429, 500].map((status): typeof globalThis.fetch => async () => new Response(`${apiKey} ${input}`, { status })),
    async () => { throw new Error(`${apiKey} ${input}`); }, async () => new Response('invalid JSON'),
  ];
  for (const fetch of fetchers) {
    const result = await new BlacklistModule({ providers: [createGoogleSafeBrowsingProvider({ apiKey, fetch })] }).analyze(input);
    assert.equal(result.status, 'error');
    assert.equal(result.details.status, 'unknown');
    assert.deepEqual(result.evidence, []);
    assert.ok(!JSON.stringify(result.details.errors).includes(apiKey));
    assert.ok(!JSON.stringify(result.details.errors).includes(input));
  }
});

test('invalid input and pre-aborted signals cannot invoke Google; checker aborts a timed-out request', async () => {
  let calls = 0;
  const provider = createGoogleSafeBrowsingProvider({ apiKey, fetch: async () => { calls++; return Response.json({}); } });
  for (const url of ['/login', 'file:///etc/passwd', 'https://user:secret@example.com/', 'https:example.com']) {
    await assert.rejects(provider.check(url, context()));
  }
  await assert.rejects(provider.check(input, { signal: AbortSignal.abort() }), /request aborted/);
  assert.equal(calls, 0);
  let signal: AbortSignal | undefined;
  const slow = createGoogleSafeBrowsingProvider({ apiKey, fetch: async (_endpoint, init) => {
    signal = init?.signal ?? undefined;
    return new Promise<Response>(() => {});
  } });
  const result = await createBlacklistChecker({ providers: [slow], timeoutMs: 10 })(input);
  assert.equal(result.status, 'unknown');
  assert.equal(result.errors[0]?.code, 'timeout');
  assert.equal(signal?.aborted, true);
});

test('explicit credentials are required, options are snapshotted, and legacy environment names migrate to Safe Browsing only', async () => {
  for (const key of ['', ' ', 'bad\nkey', undefined]) {
    assert.throws(() => createGoogleSafeBrowsingProvider({ apiKey: key as string }), /API key/);
  }
  assert.throws(() => createGoogleSafeBrowsingProvider({ apiKey, addressFamily: 0 as 4 }), /addressFamily/);
  const options = { apiKey, fetch: (async (_endpoint, init) => {
    assert.equal(new Headers(init?.headers).get('x-goog-api-key'), apiKey);
    return Response.json({});
  }) as typeof globalThis.fetch };
  const provider = createGoogleSafeBrowsingProvider(options);
  options.apiKey = 'changed';
  options.fetch = async () => { throw new Error('Must not use changed options'); };
  assert.deepEqual(await provider.check(input, context()), { matched: false });
  const server = createServerPipelineOptions(new MlPhishingModule(), {
    GOOGLE_WEB_RISK_API_KEY: apiKey, GOOGLE_WEB_RISK_ADDRESS_FAMILY: '6',
  });
  assert.deepEqual(server.blacklist?.providers?.map(({ name }) => name), ['google-safe-browsing']);
  assert.deepEqual(server.assessment?.trustedBlacklistSources, ['google-safe-browsing']);
});
