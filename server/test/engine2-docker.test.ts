import assert from 'node:assert/strict';
import test from 'node:test';
import { createDockerJobFactory } from '../src/engines/engine2/zap/docker.js';
import type { DockerRunner } from '../src/modules/web-security/integrations/docker.js';
import { approved, config } from './helpers/engine2.js';

function fakeDocker(unsafe = false) {
  const calls: { args: string[]; input?: string }[] = []; let volume = '';
  const docker: DockerRunner = async (args, options) => {
    calls.push({ args, input: options?.input });
    if (args[0] === 'info') return 'linux';
    if (args[0] === 'volume' && args[1] === 'create') volume = args.at(-1)!;
    if (args[0] === 'inspect') {
      const zap = args[1]!.includes('-zap-');
      return JSON.stringify([{ HostConfig: { NetworkMode: zap && !unsafe ? 'none' : 'bridge', ReadonlyRootfs: true, Privileged: false, CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges'], PortBindings: null },
        Config: { User: '1000:1000' },
        NetworkSettings: { Networks: { [zap && !unsafe ? 'none' : 'bridge']: { NetworkID: 'network' } } }, Mounts: [{ Type: 'volume', Name: volume, Destination: '/gateway', RW: !zap }] }]);
    }
    if (args[0] === 'exec' && options?.input?.startsWith('{')) {
      const req = JSON.parse(options.input);
      if (req.component) return JSON.stringify(req.name === 'version' ? { version: '2.17.0' } : req.name === 'newContext' ? { contextId: '1' } : { Result: 'OK' });
    }
    if (args[0] === 'exec' && args.at(-1)?.includes('engine2-stats')) return '{"forwarded":1,"denied":0,"failures":0,"exhausted":false}';
    return '';
  };
  return { docker, calls };
}
test('Docker adapter uses network-none ZAP, TLS policy gateway, private API and per-job cleanup', async () => {
  const { docker, calls } = fakeDocker(); const cfg = config();
  const scope = await approved('passive', cfg); const job = await createDockerJobFactory(cfg, docker)(scope, new AbortController().signal);
  assert.equal(job.contextId, '1');
  const runs = calls.filter((c) => c.args[0] === 'run'); assert.equal(runs.length, 2);
  assert.ok(runs.some((c) => c.args.includes('none') && c.args.includes('--read-only')));
  assert.ok(!runs.some((c) => c.args.includes('-p') || c.args.includes('--privileged') || c.args.some((a) => a.includes('docker.sock'))));
  const policyEnv = runs.flatMap((r) => r.args).find((a) => a.startsWith('ENGINE2_GATEWAY_POLICY='))!;
  assert.ok(!policyEnv.includes('authorizationToken')); assert.ok(!JSON.stringify(job).includes('authorizationToken'));
  await job.enterPhase('crawl', new AbortController().signal);
  await assert.rejects(job.enterPhase('active', new AbortController().signal));
  assert.equal((await job.statistics(new AbortController().signal)).forwarded, 1);
  await job.close(); await job.close();
  assert.equal(calls.filter((c) => c.args[0] === 'rm').length, 2);
  assert.equal(calls.filter((c) => c.args[0] === 'volume' && c.args[1] === 'rm').length, 1);
});
test('Docker isolation mismatch fails closed and cleans resources before any spider/active scan', async () => {
  const { docker, calls } = fakeDocker(true); const cfg = config();
  await assert.rejects(createDockerJobFactory(cfg, docker)(await approved('passive', cfg), new AbortController().signal));
  assert.ok(calls.some((c) => c.args[0] === 'rm'));
  assert.ok(!calls.some((c) => c.input?.includes('"name":"scan"')));
});
test('missing Docker is a clear optional-backend error, not an unhandled CLI message', async () => {
  const cfg = config();
  await assert.rejects(createDockerJobFactory(cfg, async () => { throw new Error('secret daemon detail'); })(await approved('passive', cfg), new AbortController().signal),
    (error: unknown) => error instanceof Error && error.message.includes('unavailable') && !error.message.includes('secret'));
});
