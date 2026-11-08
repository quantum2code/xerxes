import assert from 'node:assert/strict';
import test from 'node:test';
import { DAG } from '../src/pipeline/dag.js';
import { ExecutionContext } from '../src/pipeline/execution-context.js';
import { PipelineRunner } from '../src/pipeline/pipeline-runner.js';
import { StateManager, TaskState } from '../src/pipeline/state-manager.js';
import { Task } from '../src/pipeline/task.js';
import { buildThreatDetectionPipeline } from '../src/pipelines/threat-detection-pipeline.js';
import {
  createBlacklistHandler, createBrandImpersonationHandler, createHttpRedirectHandler,
  createMlPhishingHandler, handleBasicUrlAnalysis, handleValidateUrl,
} from '../src/tasks/threat-detection/index.js';
import { URL_FEATURE_NAMES } from '../src/modules/threat-detection/shared/url-features.js';
import type { ModuleResult } from '../src/modules/threat-detection/contracts/module-result.js';
import { DETECTOR_MODULES } from '../src/modules/threat-detection/contracts/evidence.js';
import type { ThreatAssessmentReport } from '../src/modules/threat-detection/assessment/index.js';
import type { BasicUrlAnalysis } from '../src/modules/threat-detection/basic-url-analysis/index.js';
import type { BlacklistResult } from '../src/modules/threat-detection/blacklist/index.js';
import type { BrandImpersonationResult } from '../src/modules/threat-detection/brand-impersonation/index.js';
import { ZENODO_BRAND_CATALOG } from '../src/modules/threat-detection/brand-impersonation/index.js';
import type { HttpRedirectOptions, HttpRedirectResult } from '../src/modules/threat-detection/http-redirect/index.js';
import type { MlPhishingResult } from '../src/modules/threat-detection/ml-phishing/index.js';
import { MlPhishingModule } from '../src/modules/threat-detection/ml-phishing/index.js';

const taskNames = [
  'validateUrl', 'httpRedirectDetection', 'basicUrlAnalysis',
  'mlPhishingDetection', 'blacklistCheck', 'brandImpersonation', 'threatAssessment',
];

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

// Synthetic parameters test model plumbing only, not real phishing accuracy.
function syntheticModel() {
  return {
    format: 'xerxes-url-logistic-v1', id: 'pipeline-test-only', trainedAt: '2026-01-01T00:00:00Z',
    featureNames: [...URL_FEATURE_NAMES], means: URL_FEATURE_NAMES.map(() => 0),
    scales: URL_FEATURE_NAMES.map(() => 1), weights: URL_FEATURE_NAMES.map(() => 0),
    intercept: 2, threshold: 0.5,
  };
}

const offlineRedirects: HttpRedirectOptions = { transport: async () => ({ statusCode: 200 }) };

test('Engine 1 factory creates fresh tasks with a validation-first fan-out DAG', () => {
  const first = buildThreatDetectionPipeline();
  const second = buildThreatDetectionPipeline();
  assert.doesNotThrow(() => first.validate());
  assert.notStrictEqual(first, second);
  assert.deepEqual(first.tasks.map(({ name }) => name), taskNames);
  for (const name of taskNames) {
    assert.notStrictEqual(first.getTask(name), second.getTask(name));
    assert.deepEqual(first.getDependencies(name), name === 'validateUrl' ? []
      : name === 'threatAssessment' ? DETECTOR_MODULES : ['validateUrl']);
  }
});

test('all handlers execute once after validation and retain module outputs for the submitted URL', async () => {
  const requests: string[] = [];
  const dag = buildThreatDetectionPipeline({
    redirects: { transport: async (url) => {
      requests.push(url.href);
      return requests.length === 1 ? { statusCode: 302, location: 'https://example.org/' } : { statusCode: 200 };
    } },
    mlModel: syntheticModel(),
    blacklist: { snapshots: [{ source: 'test-feed', updatedAt: '2026-01-01T00:00:00Z', domains: ['paypaal.com'] }] },
    brandImpersonation: { brands: [{ name: 'PayPal', domains: ['paypal.com'] }] },
  });
  const calls: string[] = [];
  const instrumented = new DAG(dag.tasks.map((task) => new Task({
    name: task.name,
    dependencies: task.dependencies,
    run: (context) => {
      for (const dependency of task.dependencies) {
        assert.equal(context.state.getState(dependency), TaskState.SUCCESS);
        assert.ok(Object.hasOwn(context.results, dependency));
      }
      calls.push(task.name);
      return task.run(context);
    },
  })));
  const result = await new PipelineRunner(instrumented).run({ url: 'HTTPS://PAYPAAL.COM/login?x=1' });
  assert.deepEqual(Object.keys(result).sort(), [...taskNames].sort());
  assert.equal(calls[0], 'validateUrl');
  assert.equal(calls.at(-1), 'threatAssessment');
  assert.equal(calls.length, taskNames.length);
  assert.equal(new Set(calls).size, taskNames.length);
  assert.deepEqual(result.validateUrl, {
    url: 'https://paypaal.com/login?x=1', originalUrl: 'HTTPS://PAYPAAL.COM/login?x=1',
  });
  const redirect = (result.httpRedirectDetection as ModuleResult<HttpRedirectResult>).details;
  assert.equal(redirect.status, 'complete');
  assert.equal(redirect.finalUrl, 'https://example.org/');
  assert.equal(redirect.crossDomain, true);
  assert.equal((result.basicUrlAnalysis as ModuleResult<BasicUrlAnalysis>).details.hostname, 'paypaal.com');
  assert.equal((result.mlPhishingDetection as ModuleResult<MlPhishingResult>).details.prediction, 'phishing');
  assert.equal((result.blacklistCheck as ModuleResult<BlacklistResult>).details.status, 'matched');
  assert.equal((result.brandImpersonation as ModuleResult<BrandImpersonationResult>).details.findings[0]?.reason, 'domain_typo');
  assert.ok((result.threatAssessment as ThreatAssessmentReport).findings.length > 0);
});

test('missing optional configuration remains explicit rather than implying safety', async () => {
  const result = await new PipelineRunner(buildThreatDetectionPipeline({ redirects: offlineRedirects }))
    .run({ url: 'https://example.com' });
  assert.equal((result.mlPhishingDetection as ModuleResult<MlPhishingResult>).details.status, 'not_configured');
  assert.equal((result.blacklistCheck as ModuleResult<BlacklistResult>).details.status, 'unknown');
  assert.equal((result.brandImpersonation as ModuleResult<BrandImpersonationResult>).details.brandsChecked, 0);
});

test('Zenodo catalog is opt-in; omitted and explicitly empty pipeline catalogs stay empty', async () => {
  for (const brands of [undefined, [], ZENODO_BRAND_CATALOG]) {
    const dag = buildThreatDetectionPipeline({
      redirects: offlineRedirects,
      ...(brands === undefined ? {} : { brandImpersonation: { brands } }),
    });
    const result = await new PipelineRunner(dag).run({ url: 'https://paypaal.com/' });
    const details = (result.brandImpersonation as ModuleResult<BrandImpersonationResult>).details;
    assert.equal(details.brandsChecked, brands?.length ?? 0);
    if (brands?.length) {
      assert.ok(details.findings.some((finding) =>
        finding.brand === 'PayPal' && finding.reason === 'domain_typo'));
    } else {
      assert.deepEqual(details.findings, []);
    }
  }
});

test('invalid or credential-bearing input blocks all detectors before network/provider calls', async () => {
  let requests = 0;
  let checks = 0;
  const dag = buildThreatDetectionPipeline({
    redirects: { transport: async () => { requests++; return { statusCode: 200 }; } },
    blacklist: { providers: [{ name: 'test-provider', check: async () => { checks++; return { matched: false }; } }] },
  });
  let state: StateManager | undefined;
  const invoked: string[] = [];
  const runner = new PipelineRunner(new DAG(dag.tasks.map((task) => new Task({
    name: task.name, dependencies: task.dependencies,
    run: (context) => { state = context.state; invoked.push(task.name); return task.run(context); },
  }))));
  for (const input of [null, [], 'https://example.com', {}, { url: 42 }, { url: '/relative' },
    { url: 'file:///etc/passwd' }, { url: 'https://user:secret@example.com/' },
    { url: 'https:example.com' }, { url: 'https://example..com/' },
    { url: 'https://exam\nple.com/' }, { url: `https://example.com/${'a'.repeat(8192)}` }]) {
    invoked.length = 0;
    await assert.rejects(runner.run(input));
    assert.deepEqual(invoked, ['validateUrl']);
    assert.equal(state!.getState('validateUrl'), TaskState.FAILED);
    for (const name of taskNames.slice(1)) assert.equal(state!.getState(name), TaskState.BLOCKED);
  }
  assert.equal(requests, 0);
  assert.equal(checks, 0);
});

test('HTTP and blacklist handlers overlap while offline detectors finish independently', async () => {
  const bothStarted = deferred<void>();
  const release = deferred<void>();
  let started = 0;
  const startedWork = () => { if (++started === 2) bothStarted.resolve(); };
  const completed = new Set<string>();
  const dag = buildThreatDetectionPipeline({
    redirects: { timeoutMs: 1000, transport: async () => {
      startedWork(); await release.promise; return { statusCode: 200 };
    } },
    blacklist: { timeoutMs: 1000, providers: [{ name: 'test-provider', check: async () => {
      startedWork(); await release.promise; return { matched: false };
    } }] },
  });
  const runner = new PipelineRunner(new DAG(dag.tasks.map((task) => new Task({
    name: task.name, dependencies: task.dependencies,
    run: async (context) => {
      const output = await task.run(context);
      completed.add(task.name);
      return output;
    },
  }))));
  const pending = runner.run({ url: 'https://example.com/' });
  try {
    await bothStarted.promise;
    await new Promise<void>((resolve) => setImmediate(resolve));
    for (const name of ['validateUrl', 'basicUrlAnalysis', 'mlPhishingDetection', 'brandImpersonation']) {
      assert.ok(completed.has(name), `${name} should not wait for network detectors`);
    }
    assert.equal(completed.has('httpRedirectDetection'), false);
    assert.equal(completed.has('blacklistCheck'), false);
    assert.equal(completed.has('threatAssessment'), false);
  } finally {
    release.resolve();
    await pending;
  }
  assert.equal(completed.size, taskNames.length);
});

test('redirect and provider errors remain explicit results without aborting unrelated analysis', async () => {
  const result = await new PipelineRunner(buildThreatDetectionPipeline({
    redirects: { transport: async () => { throw new Error('network unavailable'); } },
    blacklist: { providers: [{ name: 'unavailable-provider', check: async () => { throw new Error('feed offline'); } }] },
  })).run({ url: 'https://example.com/' });
  assert.equal((result.httpRedirectDetection as ModuleResult<HttpRedirectResult>).details.status, 'error');
  assert.equal((result.blacklistCheck as ModuleResult<BlacklistResult>).details.status, 'unknown');
  assert.equal((result.blacklistCheck as ModuleResult<BlacklistResult>).details.errors[0]?.message, 'feed offline');
  const report = result.threatAssessment as ThreatAssessmentReport;
  assert.equal(report.riskLevel, 'unknown');
  assert.ok(report.incompleteModules.some(({ module }) => module === 'blacklistCheck'));
  assert.ok(report.incompleteModules.some(({ module }) => module === 'httpRedirectDetection'));
  assert.equal((result.basicUrlAnalysis as ModuleResult<BasicUrlAnalysis>).details.hostname, 'example.com');
});

test('the same Engine 1 runner isolates concurrent and subsequent runs, including after rejection', async () => {
  const runner = new PipelineRunner(buildThreatDetectionPipeline({
    redirects: offlineRedirects,
    blacklist: { providers: [{ name: 'test-provider', check: async (url) => ({ matched: url.includes('bad.example') }) }] },
  }));
  const [first, second] = await Promise.all([
    runner.run({ url: 'https://bad.example/' }), runner.run({ url: 'https://good.example/' }),
  ]);
  assert.equal((first.basicUrlAnalysis as ModuleResult<BasicUrlAnalysis>).details.hostname, 'bad.example');
  assert.equal((second.basicUrlAnalysis as ModuleResult<BasicUrlAnalysis>).details.hostname, 'good.example');
  assert.equal((first.blacklistCheck as ModuleResult<BlacklistResult>).details.status, 'matched');
  assert.equal((second.blacklistCheck as ModuleResult<BlacklistResult>).details.status, 'no_match');
  for (const name of taskNames) assert.notStrictEqual(first[name], second[name]);
  await assert.rejects(runner.run({ url: 'file:///etc/passwd' }));
  const third = await runner.run({ url: 'https://third.example/' });
  assert.equal((third.basicUrlAnalysis as ModuleResult<BasicUrlAnalysis>).details.hostname, 'third.example');
  assert.notStrictEqual(third.basicUrlAnalysis, first.basicUrlAnalysis);
});

test('detector handlers refuse execution without their validated dependency output', async () => {
  const context = new ExecutionContext({ url: 'https://example.com/' }, new StateManager());
  for (const handler of [createHttpRedirectHandler(offlineRedirects), handleBasicUrlAnalysis,
    createMlPhishingHandler(), createBlacklistHandler(), createBrandImpersonationHandler()]) {
    await assert.rejects(async () => handler(context), /Missing validateUrl result/);
  }
  assert.deepEqual(handleValidateUrl(context), { url: 'https://example.com/', originalUrl: 'https://example.com/' });
});

test('pipeline construction validates configured models, feeds, and brand catalogs before execution', () => {
  assert.throws(() => buildThreatDetectionPipeline({ mlModel: {} }), /model format/);
  assert.throws(() => buildThreatDetectionPipeline({
    mlModel: syntheticModel(), mlModule: new MlPhishingModule(),
  }), /either mlModel or mlModule/);
  assert.throws(() => buildThreatDetectionPipeline({ blacklist: { timeoutMs: 0 } }), /timeoutMs/);
  assert.throws(() => buildThreatDetectionPipeline({
    brandImpersonation: { brands: [{ name: 'Invalid', domains: ['com'] }] },
  }), /registrable domains/);
});

test('pipeline awaits a caller-preloaded async ML module with per-run validated inputs', async () => {
  const inputs: string[] = [];
  const implementation = new MlPhishingModule(syntheticModel());
  const mlModule = {
    name: 'mlPhishingDetection' as const,
    async analyze(input: string) {
      inputs.push(input);
      await new Promise<void>((resolve) => setImmediate(resolve));
      return implementation.analyze(input);
    },
  };
  const runner = new PipelineRunner(buildThreatDetectionPipeline({ redirects: offlineRedirects, mlModule }));
  const [first, second] = await Promise.all([
    runner.run({ url: 'HTTPS://EXAMPLE.COM:443/a' }), runner.run({ url: 'https://example.org/b' }),
  ]);
  assert.deepEqual(inputs.sort(), ['https://example.com/a', 'https://example.org/b']);
  for (const result of [first, second]) {
    assert.equal((result.mlPhishingDetection as ModuleResult<MlPhishingResult>).details.status, 'predicted');
    assert.ok(result.threatAssessment);
  }
  assert.notStrictEqual(first.mlPhishingDetection, second.mlPhishingDetection);
  await assert.rejects(runner.run({ url: 'https://user:secret@example.com' }));
  assert.equal(inputs.length, 2);
});

test('handlers snapshot configuration at construction rather than reading mutable options per run', async () => {
  const redirects: HttpRedirectOptions = { transport: async () => ({ statusCode: 200 }) };
  const model = syntheticModel();
  const brands = [{ name: 'PayPal', domains: ['paypal.com'] }];
  const domains = ['paypaal.com'];
  const dag = buildThreatDetectionPipeline({ redirects, mlModel: model,
    blacklist: { snapshots: [{ source: 'test-feed', updatedAt: '2026-01-01T00:00:00Z', domains }] },
    brandImpersonation: { brands },
  });
  redirects.transport = async () => { throw new Error('changed transport'); };
  model.intercept = -2;
  brands[0]!.domains[0] = 'paypaal.com';
  domains.length = 0;
  const result = await new PipelineRunner(dag).run({ url: 'https://paypaal.com/' });
  assert.equal((result.httpRedirectDetection as ModuleResult<HttpRedirectResult>).details.status, 'complete');
  assert.equal((result.mlPhishingDetection as ModuleResult<MlPhishingResult>).details.prediction, 'phishing');
  assert.equal((result.blacklistCheck as ModuleResult<BlacklistResult>).details.status, 'matched');
  assert.equal((result.brandImpersonation as ModuleResult<BrandImpersonationResult>).details.findings[0]?.reason, 'domain_typo');
  assert.ok((result.threatAssessment as ThreatAssessmentReport).findings.length > 0);
});
