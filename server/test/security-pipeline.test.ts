import assert from 'node:assert/strict';
import test from 'node:test';
import { DAG } from '../src/pipeline/dag.js';
import { PipelineRunner } from '../src/pipeline/pipeline-runner.js';
import { TaskState } from '../src/pipeline/state-manager.js';
import { Task } from '../src/pipeline/task.js';
import { buildSecurityPipeline } from '../src/pipelines/mock-pipeline.js';

test('buildSecurityPipeline returns a fresh valid DAG with mock dependencies', () => {
  const first = buildSecurityPipeline();
  const second = buildSecurityPipeline();

  assert.doesNotThrow(() => first.validate());
  assert.notStrictEqual(first, second);
  assert.deepEqual(first.tasks.map((task) => task.name), [
    'certificateValidation', 'threatIntelligence', 'threatAnalysis', 'securityAssessment',
  ]);
  assert.deepEqual(first.getDependencies('certificateValidation'), []);
  assert.deepEqual(first.getDependencies('threatIntelligence'), []);
  assert.deepEqual(first.getDependencies('threatAnalysis'), ['threatIntelligence']);
  assert.deepEqual(first.getDependencies('securityAssessment'), ['certificateValidation', 'threatAnalysis']);
  for (const task of first.tasks) {
    assert.notStrictEqual(task, second.getTask(task.name));
  }
});

test('mock tasks execute once and only after their dependencies succeed', async () => {
  const calls: string[] = [];
  const dag = buildSecurityPipeline();
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

  await new PipelineRunner(instrumented).run({ url: 'https://example.com' });
  assert.equal(calls.length, 4);
  assert.equal(new Set(calls).size, 4);
  assert.ok(calls.indexOf('threatIntelligence') < calls.indexOf('threatAnalysis'));
  assert.equal(calls.at(-1), 'securityAssessment');
});

test('downstream mock tasks consume upstream outputs', async () => {
  const dag = buildSecurityPipeline();
  const fixtures = new DAG(dag.tasks.map((task) => {
    if (task.name === 'certificateValidation') {
      return new Task({ name: task.name, run: () => ({ valid: false }) });
    }
    if (task.name === 'threatIntelligence') {
      return new Task({ name: task.name, run: () => ({ matches: ['mock-indicator'] }) });
    }
    return task;
  }));

  const result = await new PipelineRunner(fixtures).run({ url: 'https://example.com' });
  assert.deepEqual(result.threatAnalysis, { verdict: 'suspicious', score: 25 });
  assert.deepEqual(result.securityAssessment, {
    findings: ['Mock certificate validation failed', 'Mock threat intelligence match detected'],
  });
});

test('a runner built from the security DAG preserves mock outputs across isolated runs', async () => {
  const dag = buildSecurityPipeline();
  const runner = new PipelineRunner(dag);
  const first = await runner.run({ url: 'https://example.com' });
  const second = await runner.run({ url: 'https://example.org' });

  assert.deepEqual(first, {
    threatAnalysis: { verdict: 'unknown', score: 0 },
    securityAssessment: { findings: ['Mock certificate validation failed'] },
    certificateValidation: { valid: false },
    threatIntelligence: { matches: [] },
  });
  assert.deepEqual(second, first);
  assert.notStrictEqual(first, second);
  for (const name of ['threatAnalysis', 'securityAssessment', 'certificateValidation', 'threatIntelligence'] as const) {
    assert.notStrictEqual(first[name], second[name]);
  }
});
