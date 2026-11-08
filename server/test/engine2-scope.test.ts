import assert from 'node:assert/strict';
import test from 'node:test';
import { ScopeValidator, ApprovedScope } from '../src/engines/engine2/scope/index.js';
import { config, request, token } from './helpers/engine2.js';
import { contextPatterns } from '../src/engines/engine2/zap/context.js';

test('scope approval binds an unforgeable capability to authorized host/port/protocol/path', async () => {
  const result = await new ScopeValidator(config(), async () => [{ address: '8.8.8.8', family: 4 }]).validate(request);
  assert.equal(result.result.approved, true); assert.ok(result.scope instanceof ApprovedScope);
  assert.equal(result.scope.check('https://staging.example.com/app/child?x=1').allowed, true);
  for (const url of ['https://staging.example.com/application', 'https://staging.example.com/app/private/x', 'https://staging.example.com.evil.com/app', 'https://evil.staging.example.com/app', 'http://staging.example.com/app', 'https://staging.example.com:8443/app', 'https://staging.example.com/app/logout']) assert.equal(result.scope.check(url).allowed, false, url);
  assert.throws(() => ApprovedScope.assert(JSON.parse(JSON.stringify(result.result))));
  assert.ok(!JSON.stringify(result.result).includes(token));
  const patterns = contextPatterns(result.scope);
  assert.ok(patterns.includes.some((p) => new RegExp(p).test(request.url)));
  assert.ok(!patterns.includes.some((p) => new RegExp(p).test('https://staging.example.com/application')));
});
test('allowlisted subdomains use label boundaries, not string prefixes/suffixes', async () => {
  const cfg = config(); cfg.grants[0]!.rules.hosts[0]!.includeSubdomains = true;
  const { scope } = await new ScopeValidator(cfg, async () => [{ address: '8.8.8.8', family: 4 }]).validate(request);
  assert.equal(scope?.check('https://one.staging.example.com/app').allowed, true);
  assert.equal(scope?.check('https://badstaging.example.com/app').allowed, false);
});
test('unauthorized or unverified active requests are rejected before DNS', async () => {
  let lookups = 0;
  const cfg = config(); delete cfg.grants[0]!.activeVerification;
  const validator = new ScopeValidator(cfg, async () => { lookups++; return []; });
  for (const input of [{ ...request, authorizationToken: 'x'.repeat(40) }, { ...request, mode: 'active', authorized: true }, { ...request, url: 'https://other.example/app' }, { ...request, url: 'file:///etc/passwd' }]) assert.equal((await validator.validate(input)).result.approved, false);
  assert.equal(lookups, 0);
});
test('private, mapped IPv6, metadata and mixed DNS answers are rejected', async () => {
  for (const address of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '168.63.129.16', '::ffff:8.8.8.8']) {
    const result = await new ScopeValidator(config(), async () => [{ address: '8.8.8.8', family: 4 }, { address, family: address.includes(':') ? 6 : 4 }]).validate(request);
    assert.equal(result.result.approved, false);
  }
});
test('ambiguous encodings, credential syntax and path escape attempts cannot bypass scope', async () => {
  const validator = new ScopeValidator(config(), async () => [{ address: '8.8.8.8', family: 4 }]);
  for (const url of ['https://staging.example.com/app/%2fprivate', 'https://staging.example.com/app/%252e%252e/x', 'https://staging.example.com/app/../admin', 'https://u:secret@staging.example.com/app', 'https://@staging.example.com/app', 'https://staging.example.com/app;admin', 'https://staging.example.com/app#token']) assert.equal((await validator.validate({ ...request, url })).result.approved, false, url);
});
test('local profile requires verified internal Docker fixture identity; it is not a private-network allow switch', async () => {
  const cfg = config(); cfg.grants[0]!.rules.profile = 'isolated-lab';
  const rejected = await new ScopeValidator(cfg).validate(request);
  assert.equal(rejected.result.rejectionReason, 'LAB_NOT_ISOLATED');
  const result = await new ScopeValidator(cfg, undefined, async () => ({ networkId: 'lab', addresses: ['172.30.0.10'], hostname: 'staging.example.com' })).validate(request);
  assert.equal(result.result.approved, true);
  assert.equal((await new ScopeValidator(cfg, undefined, async () => ({ networkId: 'lab', addresses: ['172.30.0.10'], hostname: 'other.example' })).validate(request)).result.approved, false);
});
