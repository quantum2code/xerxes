import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalLookupUrl, canonicalUrl, canonicalizeParsedUrl, parseHttpUrl } from '../src/modules/threat-detection/shared/url.js';
import { providerUrl } from '../src/modules/threat-detection/blacklist/provider-http.js';
import { InvalidThreatDetectionInputError, validateThreatDetectionInput } from '../src/tasks/threat-detection/validate-url.js';

test('canonicalization reuses a validated URL while preserving path/query semantics', () => {
  const input = 'HTTPS://EXAMPLE.COM.:443/Path%2f?x=2&x=1&next=a+b#private';
  const parsed = parseHttpUrl(input);
  const normalized = canonicalizeParsedUrl(parsed);
  assert.strictEqual(normalized, parsed);
  assert.equal(normalized.href, 'https://example.com/Path%2f?x=2&x=1&next=a+b');
  assert.equal(canonicalUrl(input), normalized.href);
  assert.equal(canonicalLookupUrl(input), normalized.href);
  assert.strictEqual(providerUrl, canonicalLookupUrl);
});

test('canonical reputation URLs keep IPv6 and IDNA handling and reject credential sharing', () => {
  assert.equal(canonicalLookupUrl('https://[2001:4860:4860::8888]:443/path#hash'), 'https://[2001:4860:4860::8888]/path');
  assert.equal(canonicalLookupUrl('https://bücher.de./'), 'https://xn--bcher-kva.de/');
  for (const input of ['https://user:secret@example.com/', 'https://user@example.com/',
    'file:///etc/passwd', 'https:example.com', 'https://bad..com/', '/relative']) {
    assert.throws(() => canonicalLookupUrl(input));
  }
  // Generic offline URL analysis still accepts credentials; only reputation sharing rejects them.
  assert.equal(canonicalUrl('https://user:secret@example.com/#private'), 'https://user:secret@example.com/');
});

test('validation task distinguishes input errors from arbitrary detector TypeErrors', () => {
  for (const input of [null, [], {}, { url: 0 }, { url: '/relative' },
    { url: 'https://user:secret@example.com/' }, { url: 'https://bad..com' }]) {
    assert.throws(() => validateThreatDetectionInput(input), InvalidThreatDetectionInputError);
  }
  assert.ok(new InvalidThreatDetectionInputError() instanceof TypeError);
  assert.ok(!(new TypeError('detector failure') instanceof InvalidThreatDetectionInputError));
  assert.deepEqual(validateThreatDetectionInput({ url: 'HTTPS://EXAMPLE.COM:443/path', unrelated: true }), {
    url: 'https://example.com/path', originalUrl: 'HTTPS://EXAMPLE.COM:443/path',
  });
});
