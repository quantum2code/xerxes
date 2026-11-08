import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  loadPretrainedMlPhishingModule, MlPhishingModule, PRETRAINED_URL_MODEL, PretrainedMlPhishingModule,
} from '../src/modules/threat-detection/ml-phishing/index.js';
import type { MlPhishingResult } from '../src/modules/threat-detection/ml-phishing/index.js';
import type { ModuleResult } from '../src/modules/threat-detection/contracts/module-result.js';
import { PipelineRunner } from '../src/pipeline/pipeline-runner.js';
import { buildThreatDetectionPipeline } from '../src/pipelines/threat-detection-pipeline.js';

const modelPath = process.env.PHISHING_MODEL_TEST_PATH
  ?? new URL('../models/phishing-url/model.onnx', import.meta.url);

test('pretrained loader rejects invalid thresholds before loading a model', async () => {
  for (const threshold of [NaN, Infinity, -1, 0, 1, 2]) {
    await assert.rejects(loadPretrainedMlPhishingModule({ modelPath: '/nonexistent/model.onnx', threshold }), /threshold/);
  }
  assert.equal(PRETRAINED_URL_MODEL.trainedAt, null);
  assert.equal(PRETRAINED_URL_MODEL.bytes, 23_547_864);
  assert.match(PRETRAINED_URL_MODEL.sha256, /^[a-f0-9]{64}$/);
  assert.ok(PRETRAINED_URL_MODEL.url.includes(PRETRAINED_URL_MODEL.revision));
});

test('missing, truncated, and wrong-checksum model files fail closed without network', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('No network in model tests'); });
  const directory = await mkdtemp(join(tmpdir(), 'xerxes-ml-model-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'model.onnx');
  await assert.rejects(loadPretrainedMlPhishingModule({ modelPath: path }), { code: 'ENOENT' });
  await writeFile(path, 'not a model');
  await assert.rejects(loadPretrainedMlPhishingModule({ modelPath: path }), /size/);
  const file = await open(path, 'r+');
  try { await file.truncate(PRETRAINED_URL_MODEL.bytes); } finally { await file.close(); }
  await assert.rejects(loadPretrainedMlPhishingModule({ modelPath: path }), /SHA-256/);
  assert.equal(fetch.mock.callCount(), 0);
});

test('published ONNX model performs real local inference and integrates with Engine 1', {
  skip: !process.env.PHISHING_MODEL_TEST_PATH && !existsSync(modelPath)
    ? 'Provision the pinned artifact with pnpm ml:download to run real-model tests' : false,
}, async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('No network in model tests'); });
  const module = await loadPretrainedMlPhishingModule({ modelPath });
  assert.ok(module instanceof PretrainedMlPhishingModule);
  t.after(() => module.dispose());

  // Upstream's two examples. Reference values observed from the pinned, unmodified
  // ONNX graph using onnxruntime-node 1.31.1 CPU; these test parity, not accuracy.
  const examples = [
    { url: 'https://clubedemilhagem.com/home.php', probability: 0.9946732521057129, prediction: 'phishing' },
    { url: 'http://www.medicalnewstoday.com/articles/188939.php', probability: 0.15620586276054382, prediction: 'not_phishing' },
  ] as const;

  await t.test('class mapping, probability tensor, metadata, evidence, and concurrent isolation', async () => {
    const results = await Promise.all(examples.map(({ url }) => module.analyze(url)));
    for (const [index, example] of examples.entries()) {
      const result = results[index]!;
      assert.equal(result.module, 'mlPhishingDetection');
      assert.equal(result.status, 'completed');
      assert.deepEqual(result.issues, []);
      const details = result.details;
      assert.equal(details.status, 'predicted');
      if (details.status !== 'predicted') return;
      assert.equal(details.modelId, PRETRAINED_URL_MODEL.id);
      assert.equal(details.trainedAt, null);
      assert.equal(details.threshold, 0.5);
      assert.equal(details.prediction, example.prediction);
      assert.ok(Math.abs(details.phishingProbability - example.probability) < 1e-6);
      assert.deepEqual(result.evidence, [{
        module: 'mlPhishingDetection', hostname: new URL(example.url).hostname,
        target: 'submitted', code: 'ML_PREDICTION', probability: details.phishingProbability,
        threshold: 0.5, modelId: PRETRAINED_URL_MODEL.id, trainedAt: null,
      }]);
    }
    assert.notStrictEqual(results[0], results[1]);
    assert.notStrictEqual(results[0]!.details.features, results[1]!.details.features);
    assert.deepEqual(await module.analyze(examples[0].url), results[0]);
  });

  await t.test('invalid inputs and credentials reject rather than producing a score', async () => {
    for (const input of ['file:///etc/passwd', '/login', 'https:example.com', 'https://bad..com/',
      'https://user:secret@example.com/', 'https://exam\nple.com', `https://example.com/${'a'.repeat(8192)}`]) {
      await assert.rejects(module.analyze(input));
    }
    assert.equal((await module.analyze(examples[0].url)).status, 'completed');
  });

  await t.test('caller threshold changes the prediction but not the learned estimate', async () => {
    const stricter = await loadPretrainedMlPhishingModule({ modelPath, threshold: 0.999 });
    try {
      const details = (await stricter.analyze(examples[0].url)).details;
      assert.equal(details.status, 'predicted');
      if (details.status !== 'predicted') return;
      assert.equal(details.threshold, 0.999);
      assert.equal(details.prediction, 'not_phishing');
      assert.ok(Math.abs(details.phishingProbability - examples[0].probability) < 1e-6);
    } finally { await stricter.dispose(); }
  });

  await t.test('pipeline forwards the pretrained envelope and keeps unconfigured behavior', async () => {
    const redirects = { transport: async () => ({ statusCode: 200 }) };
    const runner = new PipelineRunner(buildThreatDetectionPipeline({ redirects, mlModule: module }));
    const results = await runner.run({ url: examples[0].url });
    assert.deepEqual(results.mlPhishingDetection, await module.analyze(examples[0].url));
    const unconfigured = await new PipelineRunner(buildThreatDetectionPipeline({ redirects }))
      .run({ url: examples[0].url });
    assert.equal((unconfigured.mlPhishingDetection as ModuleResult<MlPhishingResult>).details.status, 'not_configured');
    assert.equal(new MlPhishingModule().analyze(examples[0].url).status, 'not_configured');
  });

  await t.test('disposal drains in-flight work, is idempotent, and prevents subsequent inference', async () => {
    const pending = module.analyze(examples[0].url);
    const first = module.dispose();
    assert.strictEqual(module.dispose(), first);
    assert.equal((await pending).status, 'completed');
    await first;
    await assert.rejects(module.analyze(examples[0].url), /disposed/);
  });
  assert.equal(fetch.mock.callCount(), 0);
});
