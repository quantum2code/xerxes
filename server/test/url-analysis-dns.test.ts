import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { DnsAnalyzer, type RecordQuery } from '../src/modules/url-analysis/dns/resolver.js';
import { loadUrlAnalysisConfig } from '../src/modules/url-analysis/config.js';
import { resolvePublic } from '../src/shared/network/policy.js';

const config = loadUrlAnalysisConfig({});
const absent = () => Object.assign(new Error('do not report raw details'), { code: 'ENODATA' });
const query: RecordQuery = async (type) => {
  switch (type) {
    case 'A': return [{ address: '8.8.8.8', ttl: 30 }, { address: '10.0.0.1', ttl: 10 }];
    case 'AAAA': return [{ address: '2606:4700:4700::1111', ttl: 60 }];
    case 'CNAME': return ['canonical.example.com'];
    case 'MX': return [{ exchange: 'mx.example.com', priority: 10 }];
    case 'NS': return ['ns.example.com'];
    case 'TXT': return [['google-site-verification=supersecret']];
  }
};
test('DNS records, TTLs and network classification are independently collected with TXT secrets redacted', async () => {
  const result = await new DnsAnalyzer(config, query).analyze('example.com', new AbortController().signal);
  assert.equal(result.status, 'completed'); assert.equal(result.a[0]?.ttl, 30); assert.equal(result.a[1]?.network.category, 'private');
  assert.equal(result.aaaa[0]?.network.version, 6); assert.equal(result.cname[0], 'canonical.example.com');
  assert.equal(result.mx[0]?.priority, 10); assert.equal(result.txt[0]?.kind, 'verification');
  assert.ok(!JSON.stringify(result).includes('supersecret'));
});
test('ENODATA is absence, not suspiciousness or a subsystem failure', async () => {
  const result = await new DnsAnalyzer(config, async () => { throw absent(); }).analyze('example.com', new AbortController().signal);
  assert.equal(result.status, 'completed'); assert.ok(Object.values(result.queries).every((q) => q.status === 'absent'));
});
test('NXDOMAIN and temporary failures are structured while successful answers survive', async () => {
  const dns = new DnsAnalyzer(config, async (type, ...args) => {
    if (type === 'MX') throw Object.assign(new Error('secret'), { code: 'ESERVFAIL' });
    return query(type, ...args);
  });
  const result = await dns.analyze('example.com', new AbortController().signal);
  assert.equal(result.status, 'partial'); assert.equal(result.a.length, 2); assert.equal(result.errors[0]?.retryable, true);
  const missing = await new DnsAnalyzer(config, async () => { throw Object.assign(new Error(), { code: 'ENOTFOUND' }); }).analyze('missing.example', new AbortController().signal);
  assert.equal(missing.status, 'failed');
});
test('query deadlines and concurrency bounds are enforced, including queued work', async () => {
  let active = 0; let peak = 0;
  const result = await new DnsAnalyzer({ ...config, dnsTimeoutMs: 20, dnsConcurrency: 2 }, async (_type, _host, signal) => {
    active++; peak = Math.max(active, peak);
    try { await delay(100, undefined, { signal }); return []; } finally { active--; }
  }).analyze('example.com', new AbortController().signal);
  assert.equal(result.status, 'failed'); assert.ok(peak <= 2); assert.equal(active, 0);
});
test('record limits/malformed responses are explicit and cannot hide private addresses from connection validation', async () => {
  const dns = new DnsAnalyzer({ ...config, maxDnsRecords: 1 }, query);
  const result = await dns.analyze('example.com', new AbortController().signal);
  assert.equal(result.a.length, 1); assert.equal(result.queries.A.truncated, true); assert.equal(result.status, 'partial');
  await assert.rejects(resolvePublic(new URL('https://example.com'), (host) => dns.connectionAddresses(host, new AbortController().signal)), /prohibited/);
  const malformed = await new DnsAnalyzer(config, async () => [42]).analyze('example.com', new AbortController().signal);
  assert.equal(malformed.status, 'failed'); assert.equal(malformed.errors[0]?.code, 'INVALID_DNS_RESPONSE');
});
test('IPv6-only hosts are usable; temporary failures in another address family fail closed', async () => {
  const v6 = new DnsAnalyzer(config, async (type, ...args) => { if (type === 'A') throw absent(); return query(type, ...args); });
  assert.equal((await v6.connectionAddresses('example.com', new AbortController().signal))[0]?.family, 6);
  const failed = new DnsAnalyzer(config, async (type, ...args) => { if (type === 'A') throw Object.assign(new Error(), { code: 'ESERVFAIL' }); return query(type, ...args); });
  await assert.rejects(failed.connectionAddresses('example.com', new AbortController().signal));
});
