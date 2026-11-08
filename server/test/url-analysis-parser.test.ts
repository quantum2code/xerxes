import assert from 'node:assert/strict';
import test from 'node:test';
import { parseUrl } from '../src/modules/url-analysis/url/parser.js';
import { extractFeatures, entropy } from '../src/modules/url-analysis/url/features.js';
import { loadUrlAnalysisConfig } from '../src/modules/url-analysis/config.js';
import { assertNetworkTarget } from '../src/modules/url-analysis/security/ip-validation.js';

test('WHATWG normalization and PSL include multi-level and private suffixes', () => {
  const parsed = parseUrl({ url: 'HTTPS://WWW.Example.CO.UK:443/a/../login?x=secret&x=second#token' });
  assert.equal(parsed.target.href, 'https://www.example.co.uk/login?x=secret&x=second');
  assert.equal(parsed.data.domain, 'example.co.uk'); assert.equal(parsed.data.subdomain, 'www');
  assert.equal(parsed.data.port, 443); assert.equal(parsed.data.explicitPort, true);
  assert.equal(parsed.data.queryParameterCount, 2); assert.deepEqual(parsed.data.queryParameterNames, ['x', 'x']);
  assert.equal(parsed.data.hasFragment, true); assert.ok(!JSON.stringify(parsed.data).includes('secret'));
  assert.ok(parsed.data.original.startsWith('HTTPS://WWW.Example.CO.UK:443/'));
  assert.equal(parseUrl({ url: 'https://a.user.github.io' }).data.domain, 'user.github.io');
  assert.equal(parseUrl({ url: 'https://a.invented-suffix-xyz' }).data.domain, null);
});
test('Unicode and punycode hosts share ASCII identity without labelling them malicious', () => {
  const a = parseUrl({ url: 'https://bücher.de/' });
  const b = parseUrl({ url: 'https://xn--bcher-kva.de/' });
  assert.equal(a.data.asciiHostname, b.data.asciiHostname); assert.equal(a.data.unicodeHostname, 'bücher.de');
  assert.equal(extractFeatures(a).hasPunycode, true);
});
test('IPv4, IPv6 and unusual IP representations are parsed but private connections stay blocked', () => {
  for (const raw of ['http://2130706433', 'http://0177.0.0.1', 'http://0x7f000001']) {
    const p = parseUrl({ url: raw }); assert.equal(p.data.hostname, '127.0.0.1'); assert.equal(extractFeatures(p).nonCanonicalIpv4, true);
    assert.throws(() => assertNetworkTarget(p.target, loadUrlAnalysisConfig({})));
  }
  const v6 = parseUrl({ url: 'https://[2606:4700:4700::1111]:443/' });
  assert.equal(v6.data.ipVersion, 6); assert.equal(v6.data.explicitPort, true); assert.equal(v6.data.domain, null);
  assert.equal(parseUrl({ url: 'http://8.8.8.8' }).data.ipVersion, 4);
});
test('invalid URLs, credentials and unsupported schemes are rejected without echoing input', () => {
  for (const url of ['ftp://example.com', 'file:///etc/passwd', 'https:example.com', 'https://u:secret@example.com', 'http://@example.com', 'http://example.com\\@localhost', 'http://[bad]', 'http://example.com:65536', ' http://example.com']) assert.throws(() => parseUrl({ url }));
  for (const input of [null, {}, { url: 3 }, { url: 'a'.repeat(4097) }]) assert.throws(() => parseUrl(input));
});
test('features are deterministic numerical observations, including encoding, terms and unusual ports', () => {
  const p = parseUrl({ url: 'https://a-b.example.com:8443//login/%252e?verify=123&account=x' });
  const f = extractFeatures(p);
  assert.equal(f.unusualPort, true); assert.equal(f.subdomainCount, 1); assert.equal(f.digitCount, 10);
  assert.equal(f.repeatedEncoding, true); assert.equal(f.repeatedSlashes, true); assert.equal(f.terms.login, true);
  assert.equal(f.queryParameterCount, 2); assert.equal(entropy('aaaa'), 0); assert.equal(entropy('ab'), 1);
  assert.ok(!('score' in f) && !('verdict' in f));
  assert.equal(parseUrl({ url: 'https://example.com' }).data.path, '/');
  const reserved = parseUrl({ url: 'http://example.com:0' });
  assert.equal(reserved.data.port, 0); assert.throws(() => assertNetworkTarget(reserved.target, loadUrlAnalysisConfig({})));
});
test('report URLs remove fragments and redact opaque/reset path values', () => {
  const p = parseUrl({ url: 'https://example.com/reset/hunter2?token=secret#password' });
  assert.ok(!JSON.stringify(p.data).includes('hunter2')); assert.ok(!JSON.stringify(p.data).includes('secret'));
});
