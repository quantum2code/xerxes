import { createHash } from 'node:crypto';
import { loadEngine2Config } from '../../src/engines/engine2/config.js';
import { ScopeValidator } from '../../src/engines/engine2/scope/validator.js';
import { ZapClient, type ApiRequest, type ZapTransport } from '../../src/engines/engine2/zap/client.js';
import { Semaphore } from '../../src/shared/network/limits.js';
import type { ZapJob } from '../../src/engines/engine2/zap/job.js';
import type { Engine2Config } from '../../src/engines/engine2/types.js';

export const token = 'test-engine2-capability-'.repeat(3);
export const request = { url: 'https://staging.example.com/app', mode: 'passive' as const, authorizationId: 'staging', authorizationToken: token, policy: 'conservative' };
export function config(): Engine2Config {
  return { ...loadEngine2Config({ ENGINE2_ENABLED: 'true', ENGINE2_ACTIVE_ENABLED: 'true' }), pollIntervalMs: 1,
    grants: [{ id: 'staging', tokenSha256: createHash('sha256').update(token).digest('hex'), expiresAt: '2099-01-01T00:00:00.000Z', crawlAuthorized: true,
      rules: { hosts: [{ hostname: 'staging.example.com', includeSubdomains: false }], protocols: ['https:'], ports: [443], paths: ['/app'], excludedPaths: ['/app/private'], activeMethods: ['GET', 'HEAD'], profile: 'public' },
      activeVerification: { verifiedBy: 'test-operator', evidenceRef: 'fixture-approval', verifiedAt: '2026-01-01T00:00:00.000Z' }, allowedPolicies: ['conservative'] }] };
}
export async function approved(mode: 'passive' | 'active' = 'passive', cfg = config()) {
  const approval = await new ScopeValidator(cfg, async () => [{ address: '8.8.8.8', family: 4 }]).validate({ ...request, mode });
  if (!approval.scope) throw new Error(JSON.stringify(approval.result));
  return approval.scope;
}
export async function mockJob(handler: ZapTransport, mode: 'passive' | 'active' = 'passive', cfg = config()): Promise<{ job: ZapJob; calls: ApiRequest[] }> {
  return scriptedJob(await approved(mode, cfg), cfg, handler);
}
export function scriptedJob(scope: Awaited<ReturnType<typeof approved>>, cfg: Engine2Config, handler: ZapTransport): { job: ZapJob; calls: ApiRequest[] } {
  const calls: ApiRequest[] = []; const lock = new Semaphore(1);
  const endpoints = new Set<string>();
  const job: ZapJob = { id: scope.id, scope, contextId: '1', config: cfg, passiveConfigured: false,
    client: new ZapClient(async (req, signal) => { calls.push(req); return handler(req, signal); }, cfg.apiTimeoutMs),
    enterPhase: async () => {}, statistics: async () => ({ forwarded: 1, denied: 0, failures: 0, exhausted: false }),
    exclusive: (signal, run) => lock.run(signal, run), recordEndpoints: (urls) => urls.forEach((url) => endpoints.add(url)), endpoints: () => [...endpoints], close: async () => {},
  };
  return { job, calls };
}
