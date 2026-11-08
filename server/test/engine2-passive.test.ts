import assert from 'node:assert/strict';
import test from 'node:test';
import { scanPassive } from '../src/engines/engine2/passive/index.js';
import { mockJob, config } from './helpers/engine2.js';
import { normalizeAlerts } from '../src/engines/engine2/reporting/normalize.js';

export const passiveAlert = { id: '1', pluginId: '10020', sourceid: '3', alert: 'Missing framing restriction', risk: 'Low', confidence: 'Medium',
  url: 'https://staging.example.com/app?token=secret', cweid: '1021', description: 'Framing protection was not observed.', solution: 'Review frame-ancestors policy.',
  evidence: 'session=very-secret-cookie', param: '', method: 'GET', reference: 'https://www.zaproxy.org/docs/alerts/10020/' };
test('Passive queue completion retrieves actual ZAP alerts, references and severity without exposing raw evidence', async () => {
  let polls = 0;
  const { job } = await mockJob(async (req) => req.name === 'recordsToScan' ? { recordsToScan: String(polls++ ? 0 : 1) } : req.name === 'numberOfMessages' ? { numberOfMessages: '2' } : req.name === 'alerts' ? { alerts: [passiveAlert, { ...passiveAlert, id: '2', sourceid: '1' }, { ...passiveAlert, id: '3', url: 'https://other.example/' }] } : { Result: 'OK' });
  const result = await scanPassive(job, job.scope);
  assert.equal(result.status, 'partial'); // Out-of-scope alert was excluded explicitly.
  assert.equal(result.findings.length, 1); assert.equal(result.counts.low, 1); assert.equal(result.observedMessages, 2); assert.equal(result.analysedMessages, null);
  assert.equal(result.findings[0]?.zapPluginId, '10020'); assert.equal(result.findings[0]?.remediation, passiveAlert.solution);
  assert.ok(!JSON.stringify(result).includes('very-secret-cookie')); assert.ok(!JSON.stringify(result).includes('=secret'));
});
test('zero alerts with observed traffic is completed; zero traffic and pending queues are incomplete', async () => {
  for (const messages of [0, 1]) {
    const { job } = await mockJob(async (req) => req.name === 'recordsToScan' ? { recordsToScan: '0' } : req.name === 'numberOfMessages' ? { numberOfMessages: String(messages) } : req.name === 'alerts' ? { alerts: [] } : { Result: 'OK' });
    const result = await scanPassive(job, job.scope);
    assert.equal(result.status, messages ? 'completed' : 'partial'); assert.equal(result.findings.length, 0);
  }
  const { job } = await mockJob(async (req) => req.name === 'recordsToScan' ? { recordsToScan: '2' } : req.name === 'numberOfMessages' ? { numberOfMessages: '1' } : req.name === 'alerts' ? { alerts: [passiveAlert] } : { Result: 'OK' }, 'passive', { ...config(), passiveTimeoutMs: 15 });
  const result = await scanPassive(job, job.scope);
  assert.equal(result.status, 'partial'); assert.equal(result.pendingRecords, 2); assert.equal(result.findings.length, 1);
});
test('normalization excludes false positives and malformed identifiers, never inventing CVSS/CVE data', async () => {
  const { job } = await mockJob(async () => ({}));
  const result = normalizeAlerts([passiveAlert, { ...passiveAlert, id: '2', confidence: 'False Positive' }, { ...passiveAlert, id: 'secret-token' }, { ...passiveAlert, id: '4', risk: 'unknown' }], job.scope, 'passive');
  assert.equal(result.findings.length, 1); assert.equal(result.invalid, 2);
  assert.ok(result.findings.every((f) => !('cvss' in f) && !('cves' in f)));
});
test('Passive API failures cannot be reported as completed zero findings', async () => {
  const { job } = await mockJob(async () => { throw new Error('secret API-key'); });
  const result = await scanPassive(job, job.scope);
  assert.notEqual(result.status, 'completed'); assert.ok(!JSON.stringify(result).includes('secret API-key'));
});
test('normalization preserves distinct method provenance while deduplicating repeated alerts', async () => {
  const { job } = await mockJob(async () => ({}));
  const result = normalizeAlerts([passiveAlert, passiveAlert, { ...passiveAlert, id: '2', method: 'HEAD' }], job.scope, 'passive');
  assert.equal(result.findings.length, 2);
  assert.ok(result.findings.some((finding) => finding.evidence[0]?.observation.includes('Method HEAD')));
});
