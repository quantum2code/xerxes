import assert from 'node:assert/strict';
import test from 'node:test';
import { scanSpider } from '../src/engines/engine2/spider/index.js';
import { mockJob, config, approved } from './helpers/engine2.js';

test('Spider uses traditional ZAP API, captures IDs and returns normalized unique in-scope discoveries', async () => {
  const { job, calls } = await mockJob(async (req) => req.name === 'scan' ? { scan: '4' } : req.name === 'status' ? { status: '100' } : req.name === 'results' ? { results: [
    'https://staging.example.com/app', 'https://staging.example.com/app', 'https://staging.example.com/app/a?token=secret',
    'https://staging.example.com/app/private', 'https://evil.example.com/',
  ] } : { Result: 'OK' });
  const result = await scanSpider(job, job.scope);
  assert.equal(result.status, 'completed'); assert.equal(result.scanId, '4'); assert.equal(result.endpointCount, 2);
  assert.equal(result.exclusions.length, 2); assert.ok(!JSON.stringify(result).includes('=secret'));
  assert.equal(job.endpoints().length, 2); assert.ok(job.endpoints().some((url) => url.includes('=secret')));
  assert.equal(calls.find((c) => c.name === 'setOptionMaxDepth')?.params.Integer, '3');
  assert.equal(calls.find((c) => c.name === 'setOptionProcessForm')?.params.Boolean, 'false');
  assert.equal(calls.find((c) => c.name === 'scan')?.params.contextName, `engine2-${job.scope.id}`);
});
test('Spider interruption stops its scan and retains partial endpoints', async () => {
  const cfg = { ...config(), spiderTimeoutMs: 15 };
  const { job, calls } = await mockJob(async (req) => req.name === 'scan' ? { scan: '8' } : req.name === 'status' ? { status: '10' } : req.name === 'results' ? { results: ['https://staging.example.com/app/found'] } : { Result: 'OK' }, 'passive', cfg);
  const result = await scanSpider(job, job.scope);
  assert.equal(result.status, 'partial'); assert.equal(result.endpointCount, 1);
  assert.ok(calls.some((c) => c.name === 'stop' && c.params.scanId === '8'));
});
test('Spider refuses foreign/forged scopes and supports cancellation before start', async () => {
  const { job, calls } = await mockJob(async () => ({ Result: 'OK' }));
  assert.equal((await scanSpider(job, await approved())).status, 'blocked');
  assert.equal(calls.length, 0);
  const controller = new AbortController(); controller.abort();
  assert.equal((await scanSpider(job, job.scope, controller.signal)).status, 'cancelled');
  assert.equal(calls.length, 0);
});
test('lost scan-start response is not retried and triggers isolated-session stop-all cleanup', async () => {
  const { job, calls } = await mockJob(async (req) => {
    if (req.name === 'scan') throw new Error('ambiguous start'); return { Result: 'OK' };
  });
  const result = await scanSpider(job, job.scope);
  assert.equal(result.status, 'failed'); assert.equal(calls.filter((c) => c.name === 'scan').length, 1);
  assert.ok(calls.some((c) => c.name === 'stopAllScans'));
});
