import assert from 'node:assert/strict';
import { once } from 'node:events';
import { existsSync } from 'node:fs';
import test from 'node:test';
import type { TestContext } from 'node:test';
import { createApp } from '../src/app.js';
import { ZENODO_BRAND_CATALOG } from '../src/modules/threat-detection/brand-impersonation/index.js';
import { loadPretrainedMlPhishingModule, MlPhishingModule } from '../src/modules/threat-detection/ml-phishing/index.js';
import { URL_FEATURE_NAMES } from '../src/modules/threat-detection/shared/url-features.js';
import type { ThreatDetectionPipelineOptions } from '../src/pipelines/threat-detection-pipeline.js';
import { createServerPipelineOptions } from '../src/server-options.js';

const offlineRedirects = { transport: async () => ({ statusCode: 200 }) };
const keys = ['validateUrl', 'httpRedirectDetection', 'basicUrlAnalysis', 'mlPhishingDetection',
  'blacklistCheck', 'brandImpersonation', 'threatAssessment'];

async function serve(t: TestContext, options: ThreatDetectionPipelineOptions = {}) {
  const server = createApp(options).listen(0, '127.0.0.1');
  t.after(() => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return `http://127.0.0.1:${address.port}`;
}

function post(base: string, body: unknown) {
  return fetch(`${base}/api/analyze`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}

// Synthetic coefficients exercise HTTP/DAG plumbing, not model quality.
function syntheticModel() {
  return {
    format: 'xerxes-url-logistic-v1', id: 'http-test-only', trainedAt: '2026-01-01T00:00:00Z',
    featureNames: [...URL_FEATURE_NAMES], means: URL_FEATURE_NAMES.map(() => 0),
    scales: URL_FEATURE_NAMES.map(() => 1), weights: URL_FEATURE_NAMES.map(() => 0),
    intercept: 2, threshold: 0.5,
  };
}

test('health remains available and only POST /api/analyze is exposed', async (t) => {
  let calls = 0;
  const base = await serve(t, { redirects: { transport: async () => { calls++; return { statusCode: 200 }; } } });
  const health = await fetch(`${base}/health`);
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: 'ok' });
  assert.equal((await fetch(`${base}/api/analyze`)).status, 404);
  assert.equal((await fetch(`${base}/analyze`, { method: 'POST' })).status, 404);
  assert.equal(calls, 0);
});

test('POST /api/analyze runs real detectors and assessment instead of mock tasks', async (t) => {
  const requests: string[] = [];
  const base = await serve(t, {
    redirects: { transport: async (url) => {
      requests.push(url.href);
      return requests.length === 1 ? { statusCode: 302, location: 'https://example.org/' } : { statusCode: 200 };
    } },
    mlModel: syntheticModel(),
    brandImpersonation: { brands: ZENODO_BRAND_CATALOG },
    blacklist: { snapshots: [{ source: 'test-feed', updatedAt: '2026-01-01T00:00:00Z', domains: ['paypaal.com'] }] },
    assessment: { trustedBlacklistSources: ['test-feed'] },
  });
  const response = await post(base, { url: 'HTTPS://PAYPAAL.COM:443/login' });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type')!, /application\/json/);
  const result = await response.json();
  assert.deepEqual(Object.keys(result).sort(), [...keys].sort());
  assert.deepEqual(result.validateUrl, {
    url: 'https://paypaal.com/login', originalUrl: 'HTTPS://PAYPAAL.COM:443/login',
  });
  assert.deepEqual(requests, ['https://paypaal.com/login', 'https://example.org/']);
  assert.equal(result.httpRedirectDetection.details.finalUrl, 'https://example.org/');
  assert.equal(result.basicUrlAnalysis.details.hostname, 'paypaal.com');
  assert.equal(result.mlPhishingDetection.details.modelId, 'http-test-only');
  assert.equal(result.blacklistCheck.details.status, 'matched');
  assert.equal(result.brandImpersonation.details.brandsChecked, 82);
  assert.ok(result.brandImpersonation.details.findings.some((finding: { brand: string; reason: string }) =>
    finding.brand === 'PayPal' && finding.reason === 'domain_typo'));
  assert.equal(result.threatAssessment.riskLevel, 'high');
});

test('unconfigured checks remain explicit and request bodies cannot configure detectors', async (t) => {
  const base = await serve(t, { redirects: offlineRedirects });
  const response = await post(base, {
    url: 'https://paypaal.com/', mlModel: syntheticModel(),
    brandImpersonation: { brands: ZENODO_BRAND_CATALOG },
    blacklist: { snapshots: [{ source: 'injected', domains: ['paypaal.com'] }] },
  });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.mlPhishingDetection.details.status, 'not_configured');
  assert.equal(result.brandImpersonation.details.brandsChecked, 0);
  assert.equal(result.blacklistCheck.details.status, 'unknown');
  for (const module of ['mlPhishingDetection', 'brandImpersonation', 'blacklistCheck']) {
    assert.ok(result.threatAssessment.incompleteModules.some((entry: { module: string }) => entry.module === module));
  }
});

test('bad input, malformed JSON, media types, and oversized bodies return sanitized JSON without invoking detectors', async (t) => {
  let calls = 0;
  const base = await serve(t, {
    redirects: { transport: async () => { calls++; return { statusCode: 200 }; } },
    blacklist: { providers: [{ name: 'test-provider', check: async () => { calls++; return { matched: false }; } }] },
    mlModule: { name: 'mlPhishingDetection', analyze: () => { calls++; throw new Error('Must not run'); } },
  });
  for (const body of [null, [], {}, { url: 42 }, { url: '' }, { url: '/login' },
    { url: 'file:///etc/passwd' }, { url: 'https:example.com' }, { url: 'https://bad..com' },
    { url: 'https://user:secret@example.com/' }, { url: 'https://exam\nple.com' },
    { url: `https://example.com/${'a'.repeat(8192)}` }]) {
    const response = await post(base, body);
    assert.equal(response.status, 400);
    const error = await response.json();
    assert.ok(['invalid_input', 'invalid_json'].includes(error.error.code));
    assert.ok(!JSON.stringify(error).includes('secret'));
    assert.equal(error.stack, undefined);
  }
  for (const [body, type, status, code] of [
    ['{"url":', 'application/json', 400, 'invalid_json'],
    ['https://example.com', 'text/plain', 415, 'unsupported_media_type'],
    [JSON.stringify({ url: 'https://example.com', padding: 'a'.repeat(17_000) }), 'application/json', 413, 'body_too_large'],
    ['{}', 'application/json; charset=iso-8859-1', 415, 'unsupported_media_type'],
  ] as const) {
    const response = await fetch(`${base}/api/analyze`, { method: 'POST', headers: { 'Content-Type': type }, body });
    assert.equal(response.status, status);
    assert.equal((await response.json()).error.code, code);
  }
  assert.equal(calls, 0);
});

test('concurrent and subsequent HTTP requests keep separate pipeline state', async (t) => {
  const implementation = new MlPhishingModule(syntheticModel());
  const base = await serve(t, {
    redirects: offlineRedirects,
    mlModule: {
      name: 'mlPhishingDetection',
      async analyze(input) {
        await new Promise<void>((resolve) => setImmediate(resolve));
        return implementation.analyze(input);
      },
    },
  });
  const urls = ['https://example.com/a', 'https://example.org/b', 'https://example.net/c'];
  const results = await Promise.all(urls.map(async (url) => {
    const response = await post(base, { url });
    assert.equal(response.status, 200);
    return response.json();
  }));
  for (const [index, result] of results.entries()) {
    assert.equal(result.validateUrl.url, urls[index]);
    assert.equal(result.basicUrlAnalysis.details.hostname, new URL(urls[index]!).hostname);
    assert.equal(result.mlPhishingDetection.details.status, 'predicted');
    assert.ok(result.threatAssessment);
  }
  assert.equal((await post(base, { url: '/bad' })).status, 400);
  assert.equal((await post(base, { url: urls[0] })).status, 200);
});

test('unexpected detector failures return sanitized 500, not 400 or fabricated safety', async (t) => {
  const base = await serve(t, {
    redirects: offlineRedirects,
    mlModule: {
      name: 'mlPhishingDetection',
      async analyze() { throw new TypeError('sensitive-model-path secret-token'); },
    },
  });
  const response = await post(base, { url: 'https://example.com/' });
  assert.equal(response.status, 500);
  assert.deepEqual(await response.json(), { error: { code: 'analysis_failed', message: 'Threat analysis failed' } });
});

test('expected redirect/provider failures remain HTTP 200 with explicit incomplete assessment', async (t) => {
  const base = await serve(t, {
    redirects: { transport: async () => { throw new Error('network unavailable'); } },
    blacklist: { providers: [{ name: 'test-provider', check: async () => { throw new Error('provider unavailable'); } }] },
  });
  const response = await post(base, { url: 'https://example.com' });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.httpRedirectDetection.details.status, 'error');
  assert.equal(result.blacklistCheck.details.status, 'unknown');
  assert.ok(result.threatAssessment.incompleteModules.some((entry: { module: string }) => entry.module === 'httpRedirectDetection'));
});

test('server configuration connects Safe Browsing to HTTP analysis with server-owned credentials, advisory, and trust', async (t) => {
  const nativeFetch = globalThis.fetch;
  let providerCalls = 0;
  let submittedUrl: string | undefined;
  const stub = t.mock.method(globalThis, 'fetch', async (...[endpoint, init]: Parameters<typeof globalThis.fetch>) => {
    if (String(endpoint) !== 'https://safebrowsing.googleapis.com/v4/threatMatches:find') return nativeFetch(endpoint, init);
    providerCalls++;
    assert.equal(init?.method, 'POST');
    assert.equal(init?.redirect, 'error');
    assert.ok(init?.signal instanceof AbortSignal);
    const url = new URL(String(endpoint));
    const body = JSON.parse(String(init?.body));
    submittedUrl = body.threatInfo.threatEntries[0].url;
    assert.equal(url.searchParams.has('key'), false);
    assert.deepEqual(body.threatInfo.threatTypes, ['SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE']);
    assert.equal(new Headers(init?.headers).get('x-goog-api-key'), 'server-secret-key');
    return Response.json({ matches: [{ threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM',
      threatEntryType: 'URL', threat: { url: submittedUrl }, cacheDuration: '300s' }] });
  });
  const options = createServerPipelineOptions(new MlPhishingModule(), {
    GOOGLE_SAFE_BROWSING_API_KEY: 'server-secret-key',
  });
  const base = await serve(t, { ...options, redirects: offlineRedirects });
  const response = await post(base, {
    url: 'https://EXAMPLE.com/a?token=sensitive#private', GOOGLE_SAFE_BROWSING_API_KEY: 'request-key-must-not-override',
  });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(providerCalls, 1);
  assert.equal(submittedUrl, 'https://example.com/a?token=sensitive');
  assert.equal(result.blacklistCheck.status, 'completed');
  assert.equal(result.blacklistCheck.details.status, 'matched');
  assert.equal(result.blacklistCheck.details.matches[0].source, 'google-safe-browsing');
  assert.match(result.blacklistCheck.details.matches[0].details, /Potentially unsafe URL: SOCIAL_ENGINEERING/);
  assert.match(result.blacklistCheck.details.matches[0].details, /Advisory provided by Google/);
  assert.equal(result.threatAssessment.riskLevel, 'high');
  assert.ok(!JSON.stringify(result).includes('server-secret-key'));
  assert.ok(stub.mock.callCount() >= 2); // Local HTTP request plus the intercepted provider request.
});

test('server Safe Browsing configuration preserves negative checks and incomplete API failures', async (t) => {
  const nativeFetch = globalThis.fetch;
  let fail = false;
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async (...[endpoint, init]: Parameters<typeof globalThis.fetch>) => {
    if (String(endpoint) !== 'https://safebrowsing.googleapis.com/v4/threatMatches:find') return nativeFetch(endpoint, init);
    calls++;
    assert.equal(new Headers(init?.headers).get('x-goog-api-key'), 'server-key');
    return fail ? new Response('secret provider error', { status: 429 })
      : Response.json({});
  });
  const options = createServerPipelineOptions(new MlPhishingModule(), { GOOGLE_SAFE_BROWSING_API_KEY: 'server-key' });
  const base = await serve(t, { ...options, redirects: offlineRedirects });
  const first = await post(base, { url: 'https://example.com/' });
  assert.equal(first.status, 200);
  const negative = await first.json();
  assert.equal(negative.blacklistCheck.details.status, 'no_match');
  assert.deepEqual(negative.blacklistCheck.details.checkedSources, [{ source: 'google-safe-browsing', kind: 'provider' }]);
  fail = true;
  const second = await post(base, { url: 'https://example.com/' });
  assert.equal(second.status, 200);
  const unknown = await second.json();
  assert.equal(unknown.blacklistCheck.details.status, 'unknown');
  assert.ok(unknown.threatAssessment.incompleteModules.some((entry: { module: string }) => entry.module === 'blacklistCheck'));
  assert.ok(!JSON.stringify(unknown).includes('secret provider error'));
  assert.equal(calls, 2);
  assert.equal((await post(base, { url: 'https://user:secret@example.com/' })).status, 400);
  assert.equal(calls, 2);
});

test('missing Google credentials stays not_configured; old PhishTank variables are not used', async (t) => {
  const options = createServerPipelineOptions(new MlPhishingModule(), { PHISHTANK_API_KEY: 'old-key' });
  assert.deepEqual(options.blacklist?.providers, []);
  const base = await serve(t, { ...options, redirects: offlineRedirects });
  const response = await post(base, { url: 'https://example.com/', GOOGLE_SAFE_BROWSING_API_KEY: 'request-key' });
  const result = await response.json();
  assert.equal(result.blacklistCheck.status, 'not_configured');
  assert.equal(result.blacklistCheck.details.status, 'unknown');
  assert.deepEqual(result.blacklistCheck.details.checkedSources, []);
});

test('invalid Safe Browsing environment configuration fails during server setup', () => {
  for (const apiKey of ['', 'bad key', 'bad\nkey']) {
    assert.throws(() => createServerPipelineOptions(new MlPhishingModule(), { GOOGLE_SAFE_BROWSING_API_KEY: apiKey }), /API key/);
  }
});

const modelPath = process.env.PHISHING_MODEL_TEST_PATH ?? new URL('../models/phishing-url/model.onnx', import.meta.url);
test('HTTP endpoint returns real pretrained ONNX predictions with the Zenodo catalog', {
  skip: !process.env.PHISHING_MODEL_TEST_PATH && !existsSync(modelPath) ? 'Provision with pnpm ml:download' : false,
}, async (t) => {
  const mlModule = await loadPretrainedMlPhishingModule({ modelPath });
  // Register cleanup even if constructing/listening on the HTTP server fails.
  let base: string;
  try {
    base = await serve(t, { redirects: offlineRedirects, mlModule, brandImpersonation: { brands: ZENODO_BRAND_CATALOG } });
  } catch (error) {
    await mlModule.dispose();
    throw error;
  }
  t.after(() => mlModule.dispose());
  for (const [url, probability, prediction] of [
    ['https://clubedemilhagem.com/home.php', 0.9946732521057129, 'phishing'],
    ['http://www.medicalnewstoday.com/articles/188939.php', 0.15620586276054382, 'not_phishing'],
  ] as const) {
    const response = await post(base, { url });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.mlPhishingDetection.status, 'completed');
    assert.equal(result.mlPhishingDetection.details.prediction, prediction);
    assert.ok(Math.abs(result.mlPhishingDetection.details.phishingProbability - probability) < 1e-6);
    assert.equal(result.brandImpersonation.details.brandsChecked, 82);
    assert.ok(result.threatAssessment);
  }
});
