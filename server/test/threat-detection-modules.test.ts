import assert from 'node:assert/strict';
import test from 'node:test';
import {
  BasicUrlAnalysisModule, BlacklistModule, BrandImpersonationModule, HttpRedirectModule,
  MlPhishingModule, ThreatDetectionModule, analyzeBasicUrl, createBlacklistChecker,
  createBrandImpersonationDetector, createMlPhishingDetector, detectHttpRedirects,
} from '../src/modules/threat-detection/index.js';

async function analyze<TInput, TOutput>(module: ThreatDetectionModule<TInput, TOutput>, input: TInput): Promise<TOutput> {
  return module.analyze(input);
}

test('all five module classes implement the generic execution contract with distinct names', async () => {
  const modules: ThreatDetectionModule<string, unknown>[] = [
    new BasicUrlAnalysisModule(),
    new BlacklistModule(),
    new BrandImpersonationModule(),
    new HttpRedirectModule({ transport: async () => ({ statusCode: 200 }) }),
    new MlPhishingModule(),
  ];
  assert.equal(new Set(modules.map(({ name }) => name)).size, 5);
  for (const module of modules) {
    assert.ok(module instanceof ThreatDetectionModule);
    assert.equal(typeof await analyze(module, 'https://example.com/'), 'object');
  }
  const basic = await analyze(new BasicUrlAnalysisModule(), 'https://example.com/');
  assert.equal(basic.details.hostname, 'example.com'); // Generic result type is retained, not unknown.
});

test('class APIs preserve the existing function APIs and explicit unconfigured results', async () => {
  const input = 'https://example.com/';
  const redirects = { transport: async () => ({ statusCode: 200 }) };
  assert.deepEqual(new BasicUrlAnalysisModule().analyze(input).details, analyzeBasicUrl(input));
  assert.deepEqual((await new BlacklistModule().analyze(input)).details, await createBlacklistChecker()(input));
  assert.deepEqual(new BrandImpersonationModule().analyze(input).details, createBrandImpersonationDetector([])(input));
  assert.deepEqual(new MlPhishingModule().analyze(input).details, createMlPhishingDetector()(input));
  assert.deepEqual((await new HttpRedirectModule(redirects).analyze(input)).details, await detectHttpRedirects(input, redirects));
  assert.equal(new MlPhishingModule().analyze(input).status, 'not_configured');
  assert.equal(new BrandImpersonationModule().analyze(input).status, 'not_configured');
  assert.equal((await new BlacklistModule().analyze(input)).status, 'not_configured');
});
