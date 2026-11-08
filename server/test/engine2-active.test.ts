import assert from 'node:assert/strict';
import test from 'node:test';
import { scanActive } from '../src/engines/engine2/active/index.js';
import { mockJob, config } from './helpers/engine2.js';

const alert = { id: '8', pluginId: '40012', sourceid: '1', alert: 'Reflected XSS', risk: 'High', confidence: 'Medium', cweid: '79',
  url: 'https://staging.example.com/app', evidence: '<script>secret-token</script>', description: 'ZAP reported reflected script content.', solution: 'Encode untrusted output.', reference: 'https://www.zaproxy.org/docs/alerts/40012/' };
const handler = async (req: { name: string }) => req.name === 'scan' ? { scan: '4' } : req.name === 'status' ? { status: '100' } : req.name === 'alertsIds' ? { alertsIds: ['8'] } : req.name === 'alert' ? { alert } : req.name === 'accessUrl' ? { accessUrl: [{}] } : { Result: 'OK' };
test('Active is disabled for passive scopes and cannot start with out-of-scope endpoints', async () => {
  const passive = await mockJob(handler);
  assert.equal((await scanActive(passive.job, passive.job.scope, ['https://staging.example.com/app'])).status, 'blocked');
  assert.equal(passive.calls.length, 0);
  const active = await mockJob(handler, 'active');
  assert.equal((await scanActive(active.job, active.job.scope, ['https://staging.example.com/app', 'https://staging.example.com/app/private'])).status, 'blocked');
  assert.equal(active.calls.length, 0);
});
test('Active applies configured policy, records scan IDs, polls and collects only its scan alert IDs', async () => {
  const { job, calls } = await mockJob(handler, 'active');
  job.recordEndpoints(['https://staging.example.com/app']);
  const result = await scanActive(job, job.scope);
  assert.equal(result.status, 'completed'); assert.deepEqual(result.scanIds, ['4']); assert.equal(result.policy, 'conservative'); assert.equal(result.findings.length, 1);
  assert.equal(calls.find((c) => c.name === 'enableScanners')?.params.ids, '40012,40018,10028');
  assert.equal(calls.find((c) => c.name === 'scan')?.params.recurse, 'false');
  assert.ok(calls.some((c) => c.name === 'alertsIds' && c.params.scanId === '4'));
  assert.deepEqual(result.findings[0]?.owasp, ['A03:2021']); assert.ok(!JSON.stringify(result).includes('secret-token'));
});
test('Active timeout stops its scan and preserves partial findings', async () => {
  const cfg = { ...config(), activeTimeoutMs: 15 };
  const { job, calls } = await mockJob(async (req) => req.name === 'status' ? { status: '20' } : handler(req), 'active', cfg);
  job.recordEndpoints(['https://staging.example.com/app']);
  const result = await scanActive(job, job.scope);
  assert.equal(result.status, 'partial'); assert.equal(result.findings.length, 1);
  assert.ok(calls.some((c) => c.name === 'stop' && c.params.scanId === '4'));
});
test('Active handles pre-start cancellation, API failure and endpoint caps without retries', async () => {
  const cancelled = await mockJob(handler, 'active'); const controller = new AbortController(); controller.abort();
  assert.equal((await scanActive(cancelled.job, cancelled.job.scope, ['https://staging.example.com/app'], controller.signal)).status, 'cancelled'); assert.equal(cancelled.calls.length, 0);
  const failed = await mockJob(async (req) => { if (req.name === 'scan') throw new Error('ambiguous'); return handler(req); }, 'active');
  failed.job.recordEndpoints(['https://staging.example.com/app']);
  assert.notEqual((await scanActive(failed.job, failed.job.scope)).status, 'completed');
  assert.equal(failed.calls.filter((c) => c.name === 'scan').length, 1); assert.ok(failed.calls.some((c) => c.name === 'stopAllScans'));
  const capped = await mockJob(handler, 'active', { ...config(), maxActiveEndpoints: 1 });
  const result = await scanActive(capped.job, capped.job.scope, ['https://staging.example.com/app', 'https://staging.example.com/app/second']);
  assert.equal(result.status, 'partial'); assert.equal(result.testedEndpoints.length, 1);
});
