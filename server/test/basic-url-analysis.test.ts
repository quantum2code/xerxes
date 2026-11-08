import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeBasicUrl, BasicUrlAnalysisModule } from '../src/modules/threat-detection/basic-url-analysis/index.js';
import { extractUrlFeatures } from '../src/modules/threat-detection/shared/url-features.js';
import { PipelineRunner } from '../src/pipeline/pipeline-runner.js';
import { buildThreatDetectionPipeline } from '../src/pipelines/threat-detection-pipeline.js';
import type { ModuleResult } from '../src/modules/threat-detection/contracts/module-result.js';
import type { BasicUrlAnalysis } from '../src/modules/threat-detection/basic-url-analysis/index.js';

const codes = (input: string) => analyzeBasicUrl(input).signals.map(({ code }) => code);

test('basic analysis requires an explicit HTTP(S) authority rather than accepting parser repairs', () => {
  for (const input of ['https:example.com', 'https:/example.com', 'https:///example.com',
    'https:////example.com', '//example.com', '/example.com', 'ftp://example.com',
    'https://example.com\\login', 'https://example.com\\@attacker.example/',
    ' https://example.com', 'https://example.com/white space', 'https://example.com/\u00a0']) {
    assert.throws(() => analyzeBasicUrl(input), input);
  }
  assert.equal(analyzeBasicUrl('HTTPS://EXAMPLE.COM:443').normalizedUrl, 'https://example.com/');
});

test('basic analysis rejects malformed DNS labels and overlong hostnames', () => {
  for (const host of ['example..com', '.example.com', 'example.com..', '-bad.example',
    'bad-.example', 'bad_name.example', `${'a'.repeat(64)}.example`,
    Array(4).fill('a'.repeat(63)).join('.')]) {
    assert.throws(() => analyzeBasicUrl(`https://${host}/`), /hostname/, host);
  }
  assert.equal(analyzeBasicUrl(`https://${'a'.repeat(63)}.example/`).hostname, `${'a'.repeat(63)}.example`);
  const longestHost = [...Array(3).fill('a'.repeat(63)), 'b'.repeat(61)].join('.');
  assert.equal(longestHost.length, 253);
  assert.equal(analyzeBasicUrl(`https://${longestHost}./`).hostname, longestHost);
});

test('basic analysis preserves IDNA, IPv6, standard ports, and trailing-root-dot support', () => {
  const idn = analyzeBasicUrl('https://bücher.de/');
  assert.equal(idn.hostname, 'xn--bcher-kva.de');
  assert.equal(idn.unicodeHostname, 'bücher.de');
  assert.ok(idn.signals.some(({ code }) => code === 'punycode'));
  assert.equal(analyzeBasicUrl('https://[2001:4860:4860::8888]:443/').hostname, '2001:4860:4860::8888');
  assert.equal(analyzeBasicUrl('https://example.com./').hostname, 'example.com');
  assert.equal(codes('https://example.com:443/').includes('non_default_port'), false);
  assert.equal(codes('https://example.com:8443/').includes('non_default_port'), true);
});

test('local hostnames are informational structural signals without claiming DNS reachability', () => {
  for (const host of ['localhost', 'intranet', 'printer.local', 'app.localhost', 'service.internal', 'router.home.arpa']) {
    const signal = analyzeBasicUrl(`https://${host}/`).signals.find(({ code }) => code === 'local_hostname');
    assert.ok(signal, host);
    assert.equal(signal?.evidence.value, host);
  }
  for (const host of ['localhost.example.com', 'example.localhost.com', 'home.arpa.example.com', 'example.com']) {
    assert.equal(codes(`https://${host}/`).includes('local_hostname'), false, host);
  }
});

test('alternative IPv4 spellings are detected before WHATWG normalization erases them', () => {
  for (const host of ['2130706433', '0x7f000001', '0177.0.0.1', '127.1', '%31%32%37.0.0.1']) {
    const result = analyzeBasicUrl(`http://${host}:8080/`);
    assert.equal(result.hostname, '127.0.0.1', host);
    const signal = result.signals.find(({ code }) => code === 'unusual_ip_notation');
    assert.ok(signal, host);
    assert.equal(signal?.evidence.value, '127.0.0.1');
    assert.equal(result.features.hasIpHost, 1);
  }
});

test('ordinary IPv4 and alternative valid IPv6 spellings are not called unusual IPv4 notation', () => {
  for (const host of ['127.0.0.1', '127.0.0.1.', '8.8.8.8', '[::1]', '[0:0:0:0:0:0:0:1]', '[::ffff:127.0.0.1]']) {
    const result = analyzeBasicUrl(`http://${host}/`);
    assert.equal(result.features.hasIpHost, 1);
    assert.equal(result.signals.some(({ code }) => code === 'unusual_ip_notation'), false, host);
  }
});

test('keyword signals identify matched terms and their component without assigning severity', () => {
  const result = analyzeBasicUrl('https://secure.example.com/login?act=verify&token=TOPSECRET#recover');
  const signals = result.signals.filter(({ code }) => code === 'sensitive_keywords');
  assert.deepEqual(signals.map(({ location, evidence }) => ({ location, matches: evidence.matches })), [
    { location: 'hostname', matches: ['secure'] },
    { location: 'path', matches: ['login'] },
    { location: 'query', matches: ['verify'] },
    { location: 'fragment', matches: ['recover'] },
  ]);
  assert.ok(signals.every((signal) => !Object.hasOwn(signal, 'severity')));
  assert.equal(JSON.stringify(result.signals).includes('TOPSECRET'), false);
  assert.equal(Object.hasOwn(result, 'verdict'), false);
  assert.equal(Object.hasOwn(result, 'score'), false);
});

test('keyword evidence decodes once, deduplicates, and tolerates malformed escaping', () => {
  const result = analyzeBasicUrl('https://example.com/%6c%6f%67%69%6e/login?x=%76%65%72%69%66%79');
  assert.deepEqual(result.signals.find(({ location }) => location === 'path')?.evidence.matches, ['login']);
  assert.deepEqual(result.signals.find(({ location }) => location === 'query')?.evidence.matches, ['verify']);
  assert.doesNotThrow(() => analyzeBasicUrl('https://example.com/%ZZ?value=%C0%AF'));
  assert.equal(codes('https://example.com/%256c%256f%2567%2569%256e').includes('sensitive_keywords'), false);
});

test('display URL strips credentials and findings never include user information', () => {
  const result = analyzeBasicUrl('https://login:password-secret@example.com:8443/path?token=sensitive#private');
  assert.equal(result.displayUrl, 'https://example.com:8443/path?token=sensitive#private');
  assert.ok(result.normalizedUrl.includes('password-secret')); // Deliberately retained, documented sensitive field.
  assert.equal(JSON.stringify(result.signals).includes('password-secret'), false);
  const credential = result.signals.find(({ code }) => code === 'credentials');
  assert.ok(credential);
  assert.equal(credential?.location, 'userinfo');
  assert.deepEqual(credential?.evidence, { value: 'present' });
  assert.equal(result.signals.some(({ code }) => code === 'sensitive_keywords'), false);
});

test('length and count thresholds have explicit evidence and correct boundaries', () => {
  const base = 'https://example.com/';
  const makeUrl = (length: number) => base + 'a'.repeat(length - base.length);
  assert.equal(codes(makeUrl(200)).includes('long_url'), false);
  const longSignal = analyzeBasicUrl(makeUrl(201)).signals.find(({ code }) => code === 'long_url');
  assert.deepEqual(longSignal?.evidence, { value: 201, threshold: 200 });
  assert.equal(codes('https://a.b.example.com/').includes('many_subdomains'), false);
  assert.equal(codes('https://a.b.c.example.com/').includes('many_subdomains'), true);
  assert.equal(codes('https://example.com/%41%41%41%41').includes('encoded_characters'), false);
  assert.equal(codes('https://example.com/%41%41%41%41%41').includes('encoded_characters'), true);
});

test('new findings do not change the version-1 numeric ML feature definitions', () => {
  for (const input of ['https://secure.example.com/%6c%6f%67%69%6e', 'https://login:password@example.com/', 'http://2130706433/']) {
    assert.deepEqual(analyzeBasicUrl(input).features, extractUrlFeatures(input));
  }
  const encoded = analyzeBasicUrl('https://example.com/%6c%6f%67%69%6e');
  assert.equal(encoded.features.suspiciousWordCount, 0);
  assert.ok(encoded.signals.some(({ code }) => code === 'sensitive_keywords'));
});

test('module and function APIs agree and consecutive results share no mutable findings', () => {
  const module = new BasicUrlAnalysisModule();
  const input = 'https://secure.example.com/login';
  assert.deepEqual(module.analyze(input).details, analyzeBasicUrl(input));
  const first = module.analyze(input);
  first.details.signals[0]!.evidence.matches?.push('mutated');
  first.details.signals.length = 0;
  assert.ok(module.analyze(input).details.signals.length > 0);
  assert.ok(first.evidence.length > 0);
});

test('DAG basic handler sees original IPv4 notation while other detectors receive normalized input', async () => {
  const inputs: string[] = [];
  const runner = new PipelineRunner(buildThreatDetectionPipeline({ redirects: {
    transport: async (url) => { inputs.push(url.href); return { statusCode: 200 }; },
  } }));
  const result = await runner.run({ url: 'http://2130706433/' });
  assert.deepEqual(result.validateUrl, { originalUrl: 'http://2130706433/', url: 'http://127.0.0.1/' });
  assert.equal((result.basicUrlAnalysis as ModuleResult<BasicUrlAnalysis>).details.signals.some(({ code }) => code === 'unusual_ip_notation'), true);
  assert.deepEqual(inputs, ['http://127.0.0.1/']);
});
