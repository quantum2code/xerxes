import assert from 'node:assert/strict';
import test from 'node:test';
import { once } from 'node:events';
import { createApp } from '../src/app.js';
import { buildSecurityPipeline } from '../src/pipelines/security-pipeline.js';
import { PipelineRunner } from '../src/pipeline/pipeline-runner.js';
import { Engine2 } from '../src/engines/engine2/index.js';
import { WebSecurityScanner, loadConfig } from '../src/modules/web-security/index.js';
import { UrlAnalyzer } from '../src/modules/url-analysis/index.js';
import { config } from './helpers/engine2.js';

test('Engine2 is a separate opt-in DAG task with no whole-scan retry or cross-engine dependency', async () => {
  const engine = new Engine2({ ...config(), enabled: false });
  const dag = buildSecurityPipeline(new WebSecurityScanner(loadConfig({})), undefined, engine);
  assert.deepEqual(dag.getDependencies('engine2'), []); assert.equal(dag.getTask('engine2').retry.maxRetries, 0);
  assert.ok(dag.getDependencies('securityAssessment').includes('engine2'));
  const result = await new PipelineRunner(dag).run({ engine2: { url: 'http://127.0.0.1', mode: 'active', authorized: true } });
  assert.equal((result.engine2 as { status: string }).status, 'skipped');
  assert.equal((result.securityAssessment as { engine2: { status: string } }).engine2.status, 'skipped');
  assert.deepEqual(result.threatAnalysis, { verdict: 'unknown', score: 0 });
});
test('existing Express API exposes structured Engine2 output without a parallel management API', async (t) => {
  const server = createApp({ engine2: new Engine2({ ...config(), enabled: false }), scanner: new WebSecurityScanner(loadConfig({})),
    urlAnalyzer: new UrlAnalyzer(undefined, { query: async () => [], transport: async () => ({ statusCode: 200, headers: { 'content-type': 'text/html' } }) }) }).listen(0, '127.0.0.1');
  await once(server, 'listening'); t.after(() => { server.closeAllConnections(); server.close(); });
  const response = await fetch(`http://127.0.0.1:${(server.address() as { port: number }).port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"engine2":{"url":"https://example.com"}}' });
  const result = await response.json() as { engine2: { status: string }; securityAssessment: { engine2: unknown } };
  assert.equal(response.status, 200); assert.equal(result.engine2.status, 'skipped'); assert.ok(result.securityAssessment.engine2);
});
