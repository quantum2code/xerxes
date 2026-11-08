import assert from 'node:assert/strict';
import test from 'node:test';
import { once } from 'node:events';
import { createApp } from '../src/app.js';
import { buildSecurityPipeline } from '../src/pipelines/security-pipeline.js';
import { PipelineRunner } from '../src/pipeline/pipeline-runner.js';
import { WebSecurityScanner, loadConfig } from '../src/modules/web-security/index.js';
import { UrlAnalyzer } from '../src/modules/url-analysis/index.js';

test('production DAG adds independent scanner and separate backward-compatible assessment', async () => {
  const scanner = new WebSecurityScanner(loadConfig({}));
  const dag = buildSecurityPipeline(scanner);
  assert.deepEqual(dag.getDependencies('webSecurityScan'), []);
  assert.deepEqual(dag.getDependencies('securityAssessment'), ['certificateValidation', 'threatAnalysis', 'webSecurityScan']);
  const results = await new PipelineRunner(dag).run({ url: 'https://example.com' });
  const assessment = results.securityAssessment as { findings: string[]; webSecurity: { status: string } };
  assert.deepEqual(assessment.findings, ['Mock certificate validation failed']);
  assert.equal(assessment.webSecurity.status, 'blocked');
  assert.deepEqual(results.threatAnalysis, { verdict: 'unknown', score: 0 });
});
test('real scanner failure remains structured and does not block other pipeline branches', async () => {
  const scanner = new WebSecurityScanner(loadConfig({ WEB_SECURITY_REQUIRE_PASSIVE_AUTH: 'false' }), { transport: async () => { throw new Error(); } });
  const result = await new PipelineRunner(buildSecurityPipeline(scanner)).run({ url: 'https://example.com' });
  assert.equal((result.webSecurityScan as { status: string }).status, 'failed');
  assert.equal((result.securityAssessment as { webSecurity: { status: string } }).webSecurity.status, 'failed');
  assert.ok(result.certificateValidation);
});
test('HTTP endpoints expose standalone/pipeline results and sanitize malformed requests', async (t) => {
  const server = createApp({ scanner: new WebSecurityScanner(loadConfig({})), urlAnalyzer: new UrlAnalyzer(undefined, {
    query: async () => [], transport: async () => ({ statusCode: 200, headers: { 'content-type': 'text/html' } }),
  }) }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); server.close(); });
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const standalone = await fetch(`${origin}/api/web-security/scan`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'http://127.0.0.1', mode: 'active', authorized: true }) });
  assert.equal(standalone.status, 403); assert.equal((await standalone.json() as { status: string }).status, 'blocked');
  const pipeline = await fetch(`${origin}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"url":"https://example.com"}' });
  const results = await pipeline.json() as Record<string, unknown>;
  assert.ok(results.webSecurityScan); assert.ok(results.securityAssessment);
  const bad = await fetch(`${origin}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"password":"topsecret", broken}' });
  assert.equal(bad.status, 400); assert.ok(!(await bad.text()).includes('topsecret'));
});
