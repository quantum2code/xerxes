import assert from 'node:assert/strict';
import test from 'node:test';
import {
  BasicUrlAnalysisModule, BlacklistModule, BrandImpersonationModule, HttpRedirectModule,
  MlPhishingModule, ThreatAssessment, createAssessmentRules, DETECTOR_MODULES, URL_FEATURE_NAMES,
} from '../src/modules/threat-detection/index.js';
import type { Evidence, ModuleResult, ThreatAssessmentReport } from '../src/modules/threat-detection/index.js';
import { PipelineRunner } from '../src/pipeline/pipeline-runner.js';
import { buildThreatDetectionPipeline } from '../src/pipelines/threat-detection-pipeline.js';

const brands = [{ name: 'PayPal', domains: ['paypal.com'] }];
function model(intercept = -10) {
  return {
    format: 'xerxes-url-logistic-v1', id: 'synthetic-test-only', trainedAt: '2026-01-01T00:00:00Z',
    featureNames: [...URL_FEATURE_NAMES], means: URL_FEATURE_NAMES.map(() => 0), scales: URL_FEATURE_NAMES.map(() => 1),
    weights: URL_FEATURE_NAMES.map(() => 0), intercept, threshold: 0.5,
  };
}

function envelope(module: ModuleResult['module'], evidence: Evidence[] = []): ModuleResult {
  return { module, status: 'completed', evidence, details: {}, issues: [] };
}

const lookalike: Evidence = { module: 'brandImpersonation', code: 'BRAND_LOOKALIKE', target: 'submitted',
  hostname: 'paypaal.com', brand: 'PayPal', reason: 'domain_typo', officialDomains: ['paypal.com'], editDistance: 1 };
const auth: Evidence = { module: 'basicUrlAnalysis', code: 'AUTH_KEYWORD', target: 'submitted',
  hostname: 'paypaal.com', location: 'path', keywords: ['login'] };

test('detectors return factual evidence codes with diagnostics separate from assessment severity', () => {
  const result = new BasicUrlAnalysisModule().analyze('http://2130706433/login?token=TOPSECRET');
  assert.equal(result.module, 'basicUrlAnalysis');
  assert.equal(result.status, 'completed');
  assert.ok(result.evidence.some((item) => item.code === 'AUTH_KEYWORD'));
  assert.ok(result.evidence.some((item) => item.code === 'URL_STRUCTURE' && item.signal === 'unusual_ip_notation'));
  assert.ok(result.evidence.every((item) => !Object.hasOwn(item, 'severity') && item.hostname === '127.0.0.1'));
  assert.equal(JSON.stringify(result.evidence).includes('TOPSECRET'), false);
  assert.equal(result.details.hostname, '127.0.0.1');
});

test('brand resemblance alone is informational; authentication evidence on the same target corroborates it', () => {
  const assessment = new ThreatAssessment();
  const brand = envelope('brandImpersonation', [lookalike]);
  const alone = assessment.assess([brand]);
  assert.equal(alone.findings[0]?.severity, 'info');
  assert.equal(alone.riskLevel, 'unknown');
  const report = assessment.assess([brand, envelope('basicUrlAnalysis', [auth])]);
  const finding = report.findings.find(({ ruleId }) => ruleId === 'brand-impersonation');
  assert.equal(finding?.severity, 'medium');
  assert.deepEqual(finding?.evidence.map(({ code }) => code), ['BRAND_LOOKALIKE', 'AUTH_KEYWORD']);
  assert.equal(report.riskLevel, 'medium');
  assert.ok(report.incompleteModules.length > 0);
});

test('rules never combine different hostnames or submitted/redirect targets', () => {
  for (const unrelated of [{ ...auth, hostname: 'another.example' }, { ...auth, target: 'redirect' as const }]) {
    const report = new ThreatAssessment().assess([
      envelope('brandImpersonation', [lookalike]), envelope('basicUrlAnalysis', [unrelated]),
    ]);
    assert.equal(report.findings.find(({ ruleId }) => ruleId === 'brand-impersonation')?.severity, 'info');
    assert.equal(report.riskLevel, 'unknown');
  }
});

test('correlated brand and punycode observations are not separate severity boosts', () => {
  const structure: Evidence = { module: 'basicUrlAnalysis', hostname: lookalike.hostname, target: 'submitted',
    code: 'URL_STRUCTURE', signal: 'punycode', location: 'hostname', value: lookalike.hostname };
  const report = new ThreatAssessment().assess([
    envelope('brandImpersonation', [lookalike, { ...lookalike, reason: 'brand_in_domain' }]),
    envelope('basicUrlAnalysis', [structure, auth]),
  ]);
  assert.equal(report.findings.length, 1);
  assert.equal(report.riskLevel, 'medium');
});

test('blacklist trust is explicit and copied when constructing the rules', async () => {
  const result = await new BlacklistModule({ providers: [{ name: 'feed', check: async () => ({ matched: true }) }] })
    .analyze('https://example.com/');
  const untrusted = new ThreatAssessment().assess([result]);
  assert.equal(untrusted.riskLevel, 'medium');
  const trusted = ['feed'];
  const assessment = new ThreatAssessment(createAssessmentRules({ trustedBlacklistSources: trusted }));
  trusted.length = 0;
  const report = assessment.assess([result]);
  assert.equal(report.riskLevel, 'high');
  assert.equal(report.findings[0]?.ruleId, 'blacklist-match');
  assert.deepEqual(report.findings[0]?.evidence, result.evidence);
  assert.ok(report.incompleteModules.length > 0);
});

test('partial blacklist failure preserves positive evidence and assessment still runs', async () => {
  const result = await new BlacklistModule({ providers: [
    { name: 'match', check: async () => ({ matched: true }) },
    { name: 'offline', check: async () => { throw new Error('secret provider diagnostic'); } },
  ] }).analyze('https://example.com/');
  assert.equal(result.status, 'partial');
  assert.equal(result.evidence[0]?.code, 'BLACKLIST_MATCH');
  const report = new ThreatAssessment(createAssessmentRules({ trustedBlacklistSources: ['match'] })).assess([result]);
  assert.equal(report.riskLevel, 'high');
  assert.equal(report.incompleteModules.find(({ module }) => module === 'blacklistCheck')?.status, 'partial');
  assert.equal(JSON.stringify(report).includes('secret provider diagnostic'), false);
});

test('no configuration, empty feeds, and provider errors cannot masquerade as completed negative checks', async () => {
  assert.equal(new MlPhishingModule().analyze('https://example.com').status, 'not_configured');
  assert.equal(new BrandImpersonationModule().analyze('https://example.com').status, 'not_configured');
  assert.equal(new BrandImpersonationModule(brands).analyze('https://example.com').status, 'completed');
  assert.equal((await new BlacklistModule().analyze('https://example.com')).status, 'not_configured');
  const empty = await new BlacklistModule({ snapshots: [{ source: 'empty', updatedAt: '2026-01-01T00:00:00Z' }] })
    .analyze('https://example.com');
  assert.equal(empty.status, 'not_configured');
  const failed = await new BlacklistModule({ providers: [{ name: 'offline', check: async () => { throw new Error('offline'); } }] })
    .analyze('https://example.com');
  assert.equal(failed.status, 'error');
  assert.equal(new ThreatAssessment().assess([failed]).riskLevel, 'unknown');
});

test('missing modules are listed explicitly rather than treating an empty evidence list as safe', () => {
  const report = new ThreatAssessment().assess([]);
  assert.equal(report.riskLevel, 'unknown');
  assert.equal(report.incompleteModules.length, DETECTOR_MODULES.length);
  assert.ok(report.incompleteModules.every(({ status }) => status === 'missing'));
  assert.match(report.summary, /incomplete/);
});

test('completed negative checks yield low, with an explicit non-guarantee, not a safe verdict', async () => {
  const runner = new PipelineRunner(buildThreatDetectionPipeline({
    redirects: { transport: async () => ({ statusCode: 200 }) },
    blacklist: { providers: [{ name: 'negative', check: async () => ({ matched: false }) }] },
    brandImpersonation: { brands }, mlModel: model(),
  }));
  const result = await runner.run({ url: 'https://example.com/' });
  const report = result.threatAssessment as ThreatAssessmentReport;
  assert.equal(report.riskLevel, 'low');
  assert.deepEqual(report.findings, []);
  assert.deepEqual(report.incompleteModules, []);
  assert.match(report.summary, /not a safety guarantee/);
});

test('many weak URL observations never manufacture a high risk rating', () => {
  const result = new BasicUrlAnalysisModule().analyze(
    `http://a.b.c.some-long-host-name.example.com:8080/login?x=${'%41'.repeat(8)}${'a'.repeat(220)}`,
  );
  assert.ok(result.evidence.length > 5);
  const report = new ThreatAssessment().assess([result]);
  assert.ok(report.findings.every(({ severity }) => severity === 'info'));
  assert.equal(report.riskLevel, 'unknown');
});

test('ML estimates are supporting evidence, not standalone high-risk verdicts', () => {
  const prediction = new MlPhishingModule(model(10)).analyze('https://paypaal.com');
  const assessment = new ThreatAssessment();
  assert.equal(assessment.assess([prediction]).findings[0]?.severity, 'info');
  const report = assessment.assess([prediction, new BrandImpersonationModule(brands).analyze('https://paypaal.com')]);
  assert.equal(report.riskLevel, 'medium');
  assert.equal(report.findings.length, 1);
});

test('redirect observations identify the destination, downgrade, and whether it was followed', async () => {
  let requests = 0;
  const result = await new HttpRedirectModule({ transport: async () => ++requests === 1
    ? { statusCode: 302, location: 'http://destination.example/' } : { statusCode: 200 },
  }).analyze('https://source.example/');
  assert.equal(result.status, 'completed');
  assert.deepEqual(result.evidence, [{ module: 'httpRedirectDetection', target: 'redirect', hostname: 'destination.example',
    code: 'REDIRECT_HOP', fromHostname: 'source.example', fromScheme: 'https:', toScheme: 'http:', crossDomain: true, followed: true }]);
  const report = new ThreatAssessment().assess([result]);
  assert.equal(report.riskLevel, 'medium');
  assert.match(report.findings[0]!.message, /not proof of phishing/);
});

test('redirect evidence does not mistake an earlier response for following a loop', async () => {
  for (const location of ['#fragment', 'https://source.example:443/', 'https://source.example./']) {
    let requests = 0;
    const result = await new HttpRedirectModule({ transport: async () => {
      requests++;
      return { statusCode: 302, location };
    } }).analyze('https://source.example/');
    assert.equal(requests, 1);
    assert.equal(result.details.status, 'loop');
    assert.equal(result.evidence.length, 1);
    assert.equal(result.evidence[0]?.code === 'REDIRECT_HOP' && result.evidence[0].followed, false);
  }
  let requests = 0;
  const result = await new HttpRedirectModule({ transport: async () => ({
    statusCode: 302, location: ++requests === 1 ? '/next' : '/',
  }) }).analyze('https://source.example/');
  assert.equal(requests, 2);
  assert.deepEqual(result.evidence.map((item) => item.code === 'REDIRECT_HOP' && item.followed), [true, false]);
});

test('redirect evidence preserves HTTP destinations stopped by safety checks or redirect limits', async () => {
  for (const [location, maxRedirects, status] of [
    ['http://destination.example:8080/', 10, 'blocked'],
    ['http://user:SECRET@destination.example/', 10, 'blocked'],
    ['http://destination.example/', 0, 'limit'],
  ] as const) {
    let requests = 0;
    const result = await new HttpRedirectModule({ maxRedirects, transport: async () => {
      requests++;
      return { statusCode: 302, location };
    } }).analyze('https://source.example/');
    assert.equal(requests, 1);
    assert.equal(result.details.status, status);
    assert.deepEqual(result.evidence, [{ module: 'httpRedirectDetection', target: 'redirect', hostname: 'destination.example',
      code: 'REDIRECT_HOP', fromHostname: 'source.example', fromScheme: 'https:', toScheme: 'http:', crossDomain: true, followed: false }]);
    assert.equal(JSON.stringify(result.evidence).includes('SECRET'), false);
  }
});

test('redirect failures and rejected Location values remain assessable incomplete results', async () => {
  for (const location of ['https://example..com/', 'file:///etc/passwd']) {
    const result = await new HttpRedirectModule({ transport: async () => ({ statusCode: 302, location }) })
      .analyze('https://example.com');
    assert.equal(result.status, 'partial');
    assert.ok(result.issues.length > 0);
    assert.deepEqual(result.evidence, []);
    assert.equal(new ThreatAssessment().assess([result]).riskLevel, 'unknown');
  }
});

test('assessment rejects duplicate modules and incorrectly attributed evidence', () => {
  const assessment = new ThreatAssessment();
  const result = envelope('brandImpersonation', [lookalike]);
  assert.throws(() => assessment.assess([result, result]), /one result/);
  assert.throws(() => assessment.assess([envelope('basicUrlAnalysis', [lookalike])]), /originating detector/);
});

test('reports do not alias detector evidence or expose raw credentials/query values', () => {
  const result = new BasicUrlAnalysisModule().analyze('https://user:password-secret@example.com/login?token=TOPSECRET');
  const assessment = new ThreatAssessment();
  const first = assessment.assess([result]);
  assert.equal(first.riskLevel, 'medium');
  assert.equal(JSON.stringify(first).includes('password-secret'), false);
  assert.equal(JSON.stringify(first).includes('TOPSECRET'), false);
  first.findings[0]!.evidence.length = 0;
  assert.ok(assessment.assess([result]).findings[0]!.evidence.length > 0);
});

test('custom rules remain plain functions with traceable unique IDs', () => {
  const assessment = new ThreatAssessment([{ id: 'application-rule', evaluate: (evidence) => [{
    ruleId: 'application-rule', severity: 'medium', message: 'Application policy', evidence: [...evidence],
  }] }], 'application-v1');
  const report = assessment.analyze([envelope('brandImpersonation', [lookalike])]);
  assert.equal(report.policyVersion, 'application-v1');
  assert.equal(report.findings[0]?.ruleId, 'application-rule');
  assert.throws(() => new ThreatAssessment([{ id: 'same', evaluate: () => [] }, { id: 'same', evaluate: () => [] }]), /unique/);
});

test('DAG exposes the final report and honors trusted source configuration', async () => {
  const result = await new PipelineRunner(buildThreatDetectionPipeline({
    redirects: { transport: async () => ({ statusCode: 200 }) },
    blacklist: { providers: [{ name: 'application-feed', check: async () => ({ matched: true }) }] },
    assessment: { trustedBlacklistSources: ['application-feed'] },
  })).run({ url: 'https://example.com' });
  const report = result.threatAssessment as ThreatAssessmentReport;
  assert.equal(report.riskLevel, 'high');
  assert.ok(report.incompleteModules.some(({ module }) => module === 'mlPhishingDetection'));
});
