import assert from 'node:assert/strict';
import test from 'node:test';
import { once } from 'node:events';
import { createApp } from '../src/app.js';
import { buildSecurityPipeline } from '../src/pipelines/security-pipeline.js';
import { PipelineRunner } from '../src/pipeline/pipeline-runner.js';
import { UrlAnalyzer } from '../src/modules/url-analysis/index.js';
import { WebSecurityScanner, loadConfig } from '../src/modules/web-security/index.js';
import type { UrlAnalysisResult } from '../src/modules/url-analysis/types.js';

const analyzer = () => new UrlAnalyzer(undefined, { query: async () => [], transport: async () => ({ statusCode: 200, headers: { 'content-type': 'text/html' } }) });
test('application DAG registers urlAnalysis and aggregator dependencies without changing Module 4 requirements', async () => {
  const dag = buildSecurityPipeline(new WebSecurityScanner(loadConfig({})), analyzer());
  assert.doesNotThrow(() => dag.validate());
  assert.deepEqual(dag.getDependencies('urlAnalysis'), []);
  assert.deepEqual(dag.getDependencies('webSecurityScan'), []);
  assert.ok(dag.getDependencies('securityAssessment').includes('urlAnalysis'));
  const result = await new PipelineRunner(dag).run({ url: 'https://example.com/' });
  assert.equal((result.urlAnalysis as UrlAnalysisResult).features?.queryParameterCount, 0);
  const assessment = result.securityAssessment as { findings: string[]; webSecurity: { status: string }; urlAnalysis: { status: string } };
  assert.equal(assessment.urlAnalysis.status, 'completed'); assert.equal(assessment.webSecurity.status, 'blocked');
  assert.deepEqual(assessment.findings, ['Mock certificate validation failed']);
});
test('URL failure is a structured task result, allowing independent existing modules and aggregation to complete', async () => {
  const result = await new PipelineRunner(buildSecurityPipeline(new WebSecurityScanner(loadConfig({})), analyzer())).run({ url: 'file:///etc/passwd' });
  assert.equal((result.urlAnalysis as UrlAnalysisResult).status, 'failed'); assert.ok(result.threatAnalysis); assert.ok(result.securityAssessment);
});
test('standalone API and analyze pipeline expose URL analysis while rejecting malformed inputs safely', async (t) => {
  const server = createApp({ scanner: new WebSecurityScanner(loadConfig({})), urlAnalyzer: analyzer() }).listen(0, '127.0.0.1');
  await once(server, 'listening'); t.after(() => { server.closeAllConnections(); server.close(); });
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const post = (path: string, body: unknown) => fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const response = await post('/api/url-analysis', { url: 'https://example.com/login?token=secret' });
  assert.equal(response.status, 200); const data = await response.json() as UrlAnalysisResult;
  assert.equal(data.module, 'urlAnalysis'); assert.ok(!JSON.stringify(data).includes('=secret'));
  assert.equal((await post('/api/url-analysis', { url: 'file:///private' })).status, 400);
  assert.equal((await post('/api/url-analysis', { url: 'http://127.0.0.1' })).status, 403);
  const pipeline = await post('/api/analyze', { url: 'https://example.com/' });
  assert.ok((await pipeline.json() as { urlAnalysis: unknown }).urlAnalysis);
});
