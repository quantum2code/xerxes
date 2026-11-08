import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeBasicUrl } from '../src/modules/threat-detection/basic-url-analysis/index.js';
import { createBrandImpersonationDetector } from '../src/modules/threat-detection/brand-impersonation/index.js';
import { createMlPhishingDetector, validateLogisticUrlModel } from '../src/modules/threat-detection/ml-phishing/index.js';
import type { LogisticUrlModel } from '../src/modules/threat-detection/ml-phishing/index.js';
import { extractUrlFeatures, URL_FEATURE_NAMES } from '../src/modules/threat-detection/shared/url-features.js';
import { canonicalUrl, parseHttpUrl } from '../src/modules/threat-detection/shared/url.js';

// Synthetic parameters exercise inference math only; this is not a trained phishing model.
function syntheticModel(): LogisticUrlModel {
  return {
    format: 'xerxes-url-logistic-v1', id: 'synthetic-test-only', trainedAt: '2026-01-01T00:00:00Z',
    featureNames: [...URL_FEATURE_NAMES], means: URL_FEATURE_NAMES.map(() => 0),
    scales: URL_FEATURE_NAMES.map(() => 1), weights: URL_FEATURE_NAMES.map(() => 0),
    intercept: 0, threshold: 0.6,
  };
}

const catalog = [{ name: 'PayPal', domains: ['paypal.com', 'paypal.co.uk'] }];

test('shared URL parsing rejects unsupported, oversized, whitespace, and relative inputs', () => {
  for (const input of ['file:///etc/passwd', 'javascript:alert(1)', '/login', ' example.com ',
    'https://exam\nple.com', `https://example.com/${'a'.repeat(8_192)}`]) {
    assert.throws(() => parseHttpUrl(input));
  }
  assert.equal(canonicalUrl('HTTPS://EXAMPLE.COM.:443/a?b=2&a=1#fragment'), 'https://example.com/a?b=2&a=1');
});

test('basic analysis extracts public/private suffix aware domains and neutral HTTPS structure', () => {
  const result = analyzeBasicUrl('https://shop.example.co.uk/');
  assert.equal(result.registrableDomain, 'example.co.uk');
  assert.equal(result.subdomain, 'shop');
  assert.equal(result.publicSuffix, 'co.uk');
  assert.deepEqual(result.signals, []);
  assert.equal(analyzeBasicUrl('https://user.github.io/').registrableDomain, 'user.github.io');
});

test('basic analysis reports credentials, IP, HTTP, and non-default port', () => {
  const result = analyzeBasicUrl('http://user:secret@127.0.0.1:8080/login');
  for (const code of ['http', 'credentials', 'ip_host', 'non_default_port', 'sensitive_keywords']) {
    assert.ok(result.signals.some((signal) => signal.code === code));
  }
  assert.equal(result.registrableDomain, null);
  assert.equal(result.features.hasIpHost, 1);
  assert.equal(analyzeBasicUrl('https://[::1]/').features.hasIpHost, 1);
});

test('basic analysis flags punycode and suspicious structure without a risk verdict', () => {
  const result = analyzeBasicUrl(`https://a.b.c.pay-pal-help-extra.example.com/verify?x=${'%41'.repeat(10)}${'a'.repeat(200)}`);
  for (const code of ['many_subdomains', 'many_hyphens', 'encoded_characters', 'long_url']) {
    assert.ok(result.signals.some((signal) => signal.code === code));
  }
  const idn = analyzeBasicUrl('https://раypal.com/');
  assert.ok(idn.signals.some((signal) => signal.code === 'punycode'));
  assert.equal(idn.unicodeHostname, 'раypal.com');
  assert.equal(Object.hasOwn(result, 'verdict'), false);
});

test('lexical features are deterministic and follow the fixed model contract', () => {
  const features = extractUrlFeatures('https://example.com/a1?x=2&x=3');
  assert.deepEqual(Object.keys(features), [...URL_FEATURE_NAMES]);
  assert.equal(features.queryParameterCount, 2);
  assert.equal(features.usesHttps, 1);
  assert.equal(features.hasCredentials, 0);
  assert.ok(Object.values(features).every(Number.isFinite));
  assert.deepEqual(features, extractUrlFeatures('https://example.com/a1?x=2&x=3'));
});

test('ML explicitly returns not_configured without inventing a probability', () => {
  const result = createMlPhishingDetector()('https://example.com');
  assert.equal(result.status, 'not_configured');
  assert.equal(result.phishingProbability, null);
  assert.equal(result.prediction, null);
  assert.equal(result.modelId, null);
});

test('ML applies training standardization, weights, sigmoid, and threshold', () => {
  const model = syntheticModel();
  const weights = [...model.weights];
  const means = [...model.means];
  const scales = [...model.scales];
  const index = URL_FEATURE_NAMES.indexOf('urlLength');
  weights[index] = 2;
  means[index] = 10;
  scales[index] = 5;
  const detector = createMlPhishingDetector({ ...model, weights, means, scales, intercept: -1 });
  const result = detector('https://example.com');
  assert.equal(result.status, 'predicted');
  if (result.status !== 'predicted') return;
  const logit = ((result.features.urlLength - 10) / 5) * 2 - 1;
  assert.equal(result.phishingProbability, 1 / (1 + Math.exp(-logit)));
  assert.equal(result.prediction, 'phishing');
  assert.equal(createMlPhishingDetector(model)('https://example.com').prediction, 'not_phishing');
});

test('ML copies model configuration and uses a stable sigmoid', () => {
  const model = syntheticModel();
  const detector = createMlPhishingDetector(model);
  model.intercept = 1000;
  assert.equal(detector('https://example.com').phishingProbability, 0.5);
  assert.equal(createMlPhishingDetector(model)('https://example.com').phishingProbability, 1);
  model.intercept = -1000;
  assert.equal(createMlPhishingDetector(model)('https://example.com').phishingProbability, 0);
});

test('ML rejects incompatible, malformed, and non-finite artifacts', () => {
  const model = syntheticModel();
  for (const artifact of [null, {}, { ...model, format: 'other' }, { ...model, id: '' },
    { ...model, trainedAt: 'not-a-date' }, { ...model, featureNames: [...URL_FEATURE_NAMES].reverse() },
    { ...model, weights: [1] }, { ...model, means: URL_FEATURE_NAMES.map(() => NaN) },
    { ...model, scales: URL_FEATURE_NAMES.map(() => 0) }, { ...model, intercept: Infinity },
    { ...model, threshold: 0 }, { ...model, threshold: 1 }]) {
    assert.throws(() => validateLogisticUrlModel(artifact));
  }
});

test('ML rejects numerical overflow rather than returning NaN', () => {
  const model = { ...syntheticModel(), weights: URL_FEATURE_NAMES.map(() => Number.MAX_VALUE) };
  assert.throws(() => createMlPhishingDetector(model)('https://example.com'), /non-finite logit/);
});

test('brand detector recognizes official domains and their subdomains', () => {
  const detect = createBrandImpersonationDetector(catalog);
  for (const input of ['https://paypal.com/', 'https://login.paypal.com/', 'https://www.paypal.co.uk./']) {
    assert.deepEqual(detect(input).findings, []);
  }
});

test('brand detector catches domain typos, alternate TLDs, and brand-containing domains', () => {
  const detect = createBrandImpersonationDetector(catalog);
  assert.equal(detect('https://paypaal.com/').findings[0]?.reason, 'domain_typo');
  assert.equal(detect('https://paypaal.com/').findings[0]?.editDistance, 1);
  assert.equal(detect('https://paypal.net/').findings[0]?.reason, 'brand_in_domain');
  assert.equal(detect('https://paypal-security.example/').findings[0]?.reason, 'brand_in_domain');
});

test('brand detector folds Unicode lookalikes and detects deceptive subdomains', () => {
  const detect = createBrandImpersonationDetector(catalog);
  assert.equal(detect('https://раypal.com/').findings[0]?.reason, 'unicode_confusable');
  assert.equal(detect('https://paypal.com.attacker.net/').findings[0]?.reason, 'deceptive_subdomain');
  assert.equal(detect('https://paypal.com.evil.github.io/').findings[0]?.reason, 'deceptive_subdomain');
});

test('brand detector does not inspect path/query as host or misclassify IPs', () => {
  const detect = createBrandImpersonationDetector(catalog);
  for (const input of ['https://example.org/paypal.com?brand=paypal', 'http://127.0.0.1/', 'https://[::1]/']) {
    assert.deepEqual(detect(input).findings, []);
  }
});

test('brand catalog is copied and validates domain boundaries and edit options', () => {
  const brands = [{ name: 'PayPal', domains: ['paypal.com'] }];
  const detect = createBrandImpersonationDetector(brands);
  brands[0]!.domains[0] = 'paypaal.com';
  assert.equal(detect('https://paypaal.com').findings[0]?.reason, 'domain_typo');
  for (const domain of ['com', 'co.uk', 'github.io', 'login.paypal.com', 'https://paypal.com', '127.0.0.1', '-invalid.com']) {
    assert.throws(() => createBrandImpersonationDetector([{ name: 'Bad', domains: [domain] }]));
  }
  assert.throws(() => createBrandImpersonationDetector(catalog, { maxEditDistance: 3 }));
  assert.deepEqual(createBrandImpersonationDetector([])('https://paypal.net').findings, []);
});
