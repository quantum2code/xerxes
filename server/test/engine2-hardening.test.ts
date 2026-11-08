import assert from 'node:assert/strict';
import { once } from 'node:events';
import http from 'node:http';
import test from 'node:test';
import { ScopeValidator } from '../src/engines/engine2/scope/index.js';
import { scanSpider } from '../src/engines/engine2/spider/index.js';
import { scanActive } from '../src/engines/engine2/active/index.js';
import { configurePassive, scanPassive } from '../src/engines/engine2/passive/index.js';
import { passiveAlerts, activeAlerts } from '../src/engines/engine2/zap/alerts.js';
import { countSchema, progressSchema } from '../src/engines/engine2/zap/client.js';
import { createPolicyGateway } from '../src/engines/engine2/zap/gateway.js';
import { verifyLab } from '../src/engines/engine2/zap/lab.js';
import { approved, config, mockJob, request } from './helpers/engine2.js';

test('numeric API fields reject coercion to false completion', () => {
  for (const value of [null, false, true, '', ' ', '1e2', '-1', 1.5, '9007199254740993']) {
    assert.equal(countSchema.safeParse(value).success, false, String(value));
  }
  assert.equal(countSchema.parse('0'), 0); assert.equal(progressSchema.safeParse({ status: '101' }).success, false);
});
test('malformed passive pending counts remain partial even with no alerts', async () => {
  const { job } = await mockJob(async (req) => req.name === 'recordsToScan' ? { recordsToScan: null } : req.name === 'numberOfMessages' ? { numberOfMessages: '1' } : req.name === 'alerts' ? { alerts: [] } : { Result: 'OK' });
  const result = await scanPassive(job, job.scope);
  assert.equal(result.status, 'partial'); assert.equal(result.pendingRecords, null);
  assert.ok(result.errors.some((error) => error.code === 'INVALID_ZAP_RESPONSE'));
});
test('alert collection retains earlier pages/details on later API failure', async () => {
  const passive = await mockJob(async (req) => {
    if (req.params.start !== '0') throw new Error('private API detail');
    return { alerts: Array.from({ length: 100 }, (_, id) => ({ id })) };
  });
  const page = await passiveAlerts(passive.job, new AbortController().signal);
  assert.equal(page.alerts.length, 100); assert.equal(page.truncated, true); assert.equal(page.errors.length, 1);
  const active = await mockJob(async (req) => {
    if (req.name === 'alertsIds') return { alertsIds: ['1', '2'] };
    if (req.params.id === '2') throw new Error('private API detail');
    return { alert: { id: '1' } };
  }, 'active');
  const details = await activeAlerts(active.job, '1', new AbortController().signal);
  assert.deepEqual(details.alerts, [{ id: '1' }]); assert.equal(details.truncated, true);
  assert.ok(!JSON.stringify([page, details]).includes('private API detail'));
});
test('grant expiration during validation cannot produce approval, and pre-cancellation makes no DNS queries', async () => {
  const cfg = config();
  const validator = new ScopeValidator(cfg, async () => {
    cfg.grants[0]!.expiresAt = '2000-01-01T00:00:00.000Z'; return [{ address: '8.8.8.8', family: 4 }];
  });
  assert.equal((await validator.validate(request)).result.rejectionReason, 'UNAUTHORIZED');
  let calls = 0;
  const cancelled = new ScopeValidator(config(), async () => { calls++; return []; });
  assert.equal((await cancelled.validate(request, AbortSignal.abort())).result.status, 'cancelled'); assert.equal(calls, 0);
});
test('expired scopes block new traffic but allow historical passive collection without reconfiguration', async (t) => {
  const { job, calls } = await mockJob(async (req) => req.name === 'recordsToScan' ? { recordsToScan: '0' } : req.name === 'numberOfMessages' ? { numberOfMessages: '1' } : req.name === 'alerts' ? { alerts: [] } : { Result: 'OK' });
  await configurePassive(job, job.scope, new AbortController().signal);
  t.mock.method(Date, 'now', () => job.scope.expiresAt + 1);
  assert.equal((await scanSpider(job, job.scope)).status, 'blocked');
  assert.equal((await scanPassive(job, job.scope)).status, 'completed');
  assert.equal(calls.filter((call) => call.name === 'setEnabled').length, 1);
});
test('ambiguous phase entry resets to idle; reset failure closes independent scan jobs', async () => {
  for (const kind of ['spider', 'active'] as const) {
    const { job } = await mockJob(async (req) => req.name === 'scan' ? { scan: '1' } : req.name === 'status' ? { status: '100' } : req.name === 'results' ? { results: [request.url] } : req.name === 'alertsIds' ? { alertsIds: [] } : { Result: 'OK' }, kind === 'active' ? 'active' : 'passive');
    job.recordEndpoints([request.url]); const phases: string[] = []; let closed = 0;
    job.enterPhase = async (phase) => { phases.push(phase); throw new Error('lost phase acknowledgement'); };
    job.close = async () => { closed++; };
    const result = kind === 'spider' ? await scanSpider(job, job.scope) : await scanActive(job, job.scope);
    assert.notEqual(result.status, 'completed'); assert.deepEqual(phases, [kind === 'spider' ? 'crawl' : 'active', 'idle']); assert.equal(closed, 1);
  }
  const foreign = await mockJob(async () => ({})); let changes = 0;
  foreign.job.enterPhase = async () => { changes++; };
  await scanSpider(foreign.job, await approved()); assert.equal(changes, 0);
});
test('gateway denies idle/expired phases and authorization deadlines without forwarding', async (t) => {
  const cfg = { ...config(), requestIntervalMs: 1 }; let phase: 'idle' | 'crawl' = 'idle'; let deadline = Date.now() + 30000; let forwards = 0;
  const gateway = await createPolicyGateway({ rules: cfg.grants[0]!.rules, mode: 'passive', expiresAt: deadline, labAddresses: [] }, cfg, {
    phase: () => ({ mode: phase, expiresAt: deadline }), forward: async () => { forwards++; return { status: 200, headers: {}, body: Buffer.from('ok') }; },
  });
  gateway.server.listen(0, '127.0.0.1'); await once(gateway.server, 'listening'); t.after(() => gateway.close());
  const port = (gateway.server.address() as { port: number }).port;
  const get = () => new Promise<void>((resolve, reject) => {
    const req = http.get({ hostname: '127.0.0.1', port, path: request.url }, (res) => { res.resume(); res.on('end', resolve); }); req.on('error', reject);
  });
  await assert.rejects(get()); phase = 'crawl'; deadline = Date.now() - 1; await assert.rejects(get());
  assert.equal(forwards, 0); assert.equal(gateway.stats.denied, 2);
});
test('lab inspection rejects exposed ports, mounts, external networks and changed identities', async () => {
  const cfg = config();
  const network = { Id: 'lab-id', Internal: true, Labels: { 'xerxes.engine2.lab': 'true' } };
  const fixture = { Config: { Labels: { 'xerxes.engine2.fixture': 'true' } }, Mounts: [], HostConfig: { NetworkMode: cfg.labNetwork, Privileged: false, PortBindings: null },
    NetworkSettings: { Networks: { [cfg.labNetwork]: { NetworkID: network.Id, IPAddress: '172.30.0.2', GlobalIPv6Address: '' } } } };
  const inspect = (net: unknown, target: unknown) => verifyLab(cfg, async (args) => JSON.stringify([args[0] === 'network' ? net : target]));
  assert.equal((await inspect(network, fixture)).hostname, cfg.labTargetContainer);
  await assert.rejects(inspect({ ...network, Internal: false }, fixture));
  await assert.rejects(inspect(network, { ...fixture, Mounts: [{ Type: 'bind' }] }));
  await assert.rejects(inspect(network, { ...fixture, HostConfig: { ...fixture.HostConfig, PortBindings: { '80/tcp': [{}] } } }));
  await assert.rejects(inspect({ ...network, Id: 'changed' }, fixture));
  await assert.rejects(inspect(network, { ...fixture, NetworkSettings: { Networks: { ...fixture.NetworkSettings.Networks, bridge: fixture.NetworkSettings.Networks[cfg.labNetwork] } } }));
});
