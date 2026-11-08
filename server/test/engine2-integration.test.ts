import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import test from 'node:test';
import { z } from 'zod';
import { loadEngine2Config, ScopeValidator, createDockerJobFactory, configurePassive, scanSpider, scanPassive, scanActive } from '../src/engines/engine2/index.js';
import { verifyLab } from '../src/engines/engine2/zap/lab.js';
import { runDocker } from '../src/modules/web-security/integrations/docker.js';

// Explicit opt-in only; these tests NEVER accept a caller-supplied target or production grant.
const enabled = process.env.ENGINE2_DOCKER_TESTS === 'true';
for (const mode of ['passive', 'active'] as const) {
  test(`live isolated ZAP ${mode}: actual fixture traffic, findings, scope enforcement and cleanup`, { skip: !enabled, timeout: 360000 }, async () => {
    const token = randomBytes(32).toString('hex');
    const cfg = loadEngine2Config({ ENGINE2_ENABLED: 'true', ENGINE2_ACTIVE_ENABLED: 'true',
      ENGINE2_ZAP_IMAGE: process.env.ENGINE2_ZAP_IMAGE, ENGINE2_GATEWAY_IMAGE: process.env.ENGINE2_GATEWAY_IMAGE,
      ENGINE2_TOTAL_TIMEOUT_MS: '300000', ENGINE2_STARTUP_TIMEOUT_MS: '120000', ENGINE2_ACTIVE_TIMEOUT_MS: '120000',
      ENGINE2_MAX_REQUESTS: '1000', ENGINE2_REQUEST_INTERVAL_MS: '50',
      ENGINE2_POLICIES: JSON.stringify([{ name: 'fixture-xss', ruleIds: ['40012'], strength: 'LOW', threshold: 'MEDIUM' }]),
      ENGINE2_GRANTS: JSON.stringify([{ id: 'integration-fixture', tokenSha256: createHash('sha256').update(token).digest('hex'),
        expiresAt: new Date(Date.now() + 600000).toISOString(), crawlAuthorized: true, allowedPolicies: ['fixture-xss'],
        activeVerification: { verifiedBy: 'isolated-integration-test', evidenceRef: 'docker/engine2/compose.yaml', verifiedAt: new Date().toISOString() },
        rules: { hosts: [{ hostname: 'xerxes-engine2-fixture', includeSubdomains: false }], protocols: ['http:'], ports: [8080], paths: ['/app'], excludedPaths: ['/app/private'], activeMethods: ['GET', 'HEAD'], profile: 'isolated-lab' },
      }]),
    });
    const validator = new ScopeValidator(cfg, undefined, (signal) => verifyLab(cfg, undefined, signal));
    const approval = await validator.validate({ url: 'http://xerxes-engine2-fixture:8080/app', mode, authorizationId: 'integration-fixture', authorizationToken: token, policy: 'fixture-xss' });
    assert.ok(approval.scope, JSON.stringify(approval.result));
    const job = await createDockerJobFactory(cfg)(approval.scope, AbortSignal.timeout(cfg.totalTimeoutMs));
    try {
      await configurePassive(job, approval.scope, AbortSignal.timeout(30000));
      const spider = await scanSpider(job, approval.scope);
      assert.equal(spider.status, 'completed', JSON.stringify(spider)); assert.ok(spider.endpointCount >= 2);
      assert.ok(spider.discoveredUrls.every((url) => approval.scope!.includes(url).allowed));
      const passive = await scanPassive(job, approval.scope);
      assert.equal(passive.status, 'completed', JSON.stringify(passive)); assert.ok((passive.observedMessages ?? 0) > 0);
      assert.ok(passive.findings.some((finding) => finding.zapPluginId === '10020'), 'Expected the real ZAP missing anti-clickjacking header rule');
      if (mode === 'active') {
        const active = await scanActive(job, approval.scope, ['http://xerxes-engine2-fixture:8080/app/search?q=hello']);
        assert.equal(active.status, 'completed', JSON.stringify(active)); assert.equal(active.scanIds.length, 1);
        assert.ok(active.findings.some((finding) => finding.zapPluginId === '40012'), 'Expected the real reflected-XSS rule on this intentionally vulnerable fixture');
      }
      // An explicit management request still cannot bypass the independent network gateway.
      const before = await job.statistics(AbortSignal.timeout(10000));
      await job.enterPhase('crawl', AbortSignal.timeout(10000));
      try {
        await job.client.call('core', 'action', 'accessUrl', { url: 'http://xerxes-engine2-fixture:8080/app/private', followRedirects: 'false' }, z.unknown(), AbortSignal.timeout(10000)).catch(() => {});
      } finally { await job.enterPhase('idle', AbortSignal.timeout(10000)); }
      const after = await job.statistics(AbortSignal.timeout(10000));
      assert.equal(after.forwarded, before.forwarded); assert.ok(after.denied > before.denied);
    } finally { await job.close(); }
    const resources = await runDocker(['ps', '-aq', '--filter', `label=xerxes.engine2.job=${job.id}`]);
    const volumes = await runDocker(['volume', 'ls', '-q', '--filter', `label=xerxes.engine2.job=${job.id}`]);
    assert.equal(resources.trim(), ''); assert.equal(volumes.trim(), '');
  });
}
