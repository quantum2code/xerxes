import assert from 'node:assert/strict';
import test from 'node:test';
import { Engine2 } from '../src/engines/engine2/index.js';
import { ScopeValidator } from '../src/engines/engine2/scope/index.js';
import { Engine2Failure } from '../src/engines/engine2/errors.js';
import { config, request, scriptedJob } from './helpers/engine2.js';
import type { ZapJob } from '../src/engines/engine2/zap/job.js';
import type { ApiRequest } from '../src/engines/engine2/zap/client.js';

function fixture(closeFails = false) {
  const cfg = config(); const jobs: ZapJob[] = []; const calls: ApiRequest[] = []; let closed = 0;
  const engine = new Engine2(cfg, { validator: new ScopeValidator(cfg, async () => [{ address: '8.8.8.8', family: 4 }]), jobs: async (scope) => {
    const scripted = scriptedJob(scope, cfg, async (req) => {
      calls.push(req);
      if (req.name === 'scan') return { scan: req.component === 'spider' ? '1' : '2' };
      if (req.name === 'status') return { status: '100' };
      if (req.name === 'results') return { results: [scope.target] };
      if (req.name === 'recordsToScan') return { recordsToScan: '0' };
      if (req.name === 'numberOfMessages') return { numberOfMessages: '1' };
      if (req.name === 'alerts') return { alerts: [] };
      if (req.name === 'alertsIds') return { alertsIds: [] };
      return { Result: 'OK' };
    });
    scripted.job.close = async () => { closed++; if (closeFails) throw new Engine2Failure('CLEANUP_FAILED', 'Cleanup incomplete'); }; jobs.push(scripted.job); return scripted.job;
  } });
  return { engine, jobs, calls, cfg, closed: () => closed };
}
test('orchestrator runs scope -> spider -> passive, without automatic active escalation', async () => {
  const f = fixture(); const result = await f.engine.scan(request);
  assert.equal(result.status, 'completed'); assert.equal(result.scope.approved, true); assert.equal(result.spider.status, 'completed'); assert.equal(result.passive.status, 'completed');
  assert.equal(result.active.status, 'skipped'); assert.equal(result.findings.length, 0); assert.equal(f.closed(), 1);
  assert.ok(f.calls.findIndex((c) => c.component === 'pscan' && c.name === 'setEnabled') < f.calls.findIndex((c) => c.component === 'spider' && c.name === 'scan'));
  assert.equal(f.calls.filter((c) => c.component === 'pscan' && c.name === 'setEnabled').length, 1);
  assert.ok(!f.calls.some((c) => c.component === 'ascan'));
});
test('active mode runs only explicitly authorized configured policy and exposes every module status', async () => {
  const f = fixture(); const result = await f.engine.scan({ ...request, mode: 'active' });
  assert.equal(result.status, 'completed'); assert.equal(result.active.status, 'completed'); assert.equal(result.active.policy, 'conservative');
  assert.equal(f.closed(), 1); assert.ok(!('score' in result) && !('verdict' in result));
});
test('unavailable backend, disabled engine, invalid permission and cleanup failures are explicit', async () => {
  const cfg = config(); const validator = new ScopeValidator(cfg, async () => [{ address: '8.8.8.8', family: 4 }]);
  const unavailable = await new Engine2(cfg, { validator, jobs: async () => { throw new Engine2Failure('ZAP_UNAVAILABLE', 'Optional backend unavailable'); } }).scan(request);
  assert.equal(unavailable.status, 'unavailable'); assert.equal(unavailable.spider.status, 'skipped');
  assert.equal((await new Engine2({ ...cfg, enabled: false }).scan(request)).status, 'skipped');
  const denied = fixture(); assert.equal((await denied.engine.scan({ ...request, authorizationToken: 'x'.repeat(40) })).status, 'blocked'); assert.equal(denied.jobs.length, 0);
  const failed = fixture(true);
  const result = await failed.engine.scan(request);
  assert.equal(result.status, 'partial'); assert.ok(result.errors.some((e) => e.code === 'CLEANUP_FAILED'));
});
test('concurrent jobs retain separate scope/history and capacity is enforced', async () => {
  const cfg = { ...config(), maxConcurrentScans: 2 }; let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; }); const ids: string[] = [];
  const engine = new Engine2(cfg, { validator: new ScopeValidator(cfg, async () => [{ address: '8.8.8.8', family: 4 }]), jobs: async (scope) => {
    ids.push(scope.id); await gate;
    return scriptedJob(scope, cfg, async (req) => req.name === 'scan' ? { scan: '1' } : req.name === 'status' ? { status: '100' } : req.name === 'results' ? { results: [scope.target] } : req.name === 'recordsToScan' ? { recordsToScan: '0' } : req.name === 'numberOfMessages' ? { numberOfMessages: '1' } : req.name === 'alerts' ? { alerts: [] } : { Result: 'OK' }).job;
  } });
  const a = engine.scan({ ...request, url: request.url + '/one' }); const b = engine.scan({ ...request, url: request.url + '/two' });
  const excess = await engine.scan(request); assert.equal(excess.status, 'blocked'); release();
  const [first, second] = await Promise.all([a, b]);
  assert.equal(new Set(ids).size, 2); assert.notEqual(first.jobId, second.jobId); assert.notDeepEqual(first.spider.discoveredUrls, second.spider.discoveredUrls);
});
test('gateway failures or budget exhaustion prevent a completed zero-alert claim', async () => {
  const cfg = config();
  const engine = new Engine2(cfg, { validator: new ScopeValidator(cfg, async () => [{ address: '8.8.8.8', family: 4 }]), jobs: async (scope) => {
    const { job } = scriptedJob(scope, cfg, async (req) => req.name === 'scan' ? { scan: '1' } : req.name === 'status' ? { status: '100' } : req.name === 'results' ? { results: [scope.target] } : req.name === 'recordsToScan' ? { recordsToScan: '0' } : req.name === 'numberOfMessages' ? { numberOfMessages: '1' } : req.name === 'alerts' ? { alerts: [] } : { Result: 'OK' });
    job.statistics = async () => ({ forwarded: 5, denied: 1, failures: 0, exhausted: true }); return job;
  } });
  assert.equal((await engine.scan(request)).status, 'partial');
});
