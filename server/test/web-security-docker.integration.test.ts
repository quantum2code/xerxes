import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { loadConfig } from '../src/modules/web-security/config.js';
import { createZapBackend } from '../src/modules/web-security/integrations/zap.js';
import { runDocker, type DockerRunner } from '../src/modules/web-security/integrations/docker.js';

const body = await readFile(new URL('./fixtures/web-security.html', import.meta.url), 'utf8');
test('live Docker ZAP passively assesses local HAR without target network access', {
  skip: process.env.XERXES_TEST_ZAP_DOCKER !== '1' ? 'Opt-in: requires running Docker Linux daemon and preinstalled ZAP image' : false,
  timeout: 240_000,
}, async () => {
  const token = randomUUID();
  const config = { ...loadConfig({}), scanTimeoutMs: 180_000, zap: { ...loadConfig({}).zap, timeoutMs: 180_000 },
    grants: [{ token, origin: 'https://fixture.example', modes: ['passive' as const], expiresAt: new Date(Date.now() + 240_000).toISOString() }] };
  const result = await createZapBackend(config)({ url: 'https://fixture.example/', authorizationToken: token },
    [{ url: 'https://fixture.example/', status: 200, headers: { 'content-type': 'text/html' }, body }], 9, new AbortController().signal);
  assert.equal(result.status, 'completed', JSON.stringify(result.limitations));
  assert.ok(result.findings.length > 0);
});

test('live active ZAP is confined to a purpose-built application in an internal Docker lab', {
  skip: process.env.XERXES_TEST_ZAP_ACTIVE_LAB !== '1' ? 'Opt-in: isolated active lab; never uses an Internet target' : false,
  timeout: 300_000,
}, async () => {
  const suffix = randomUUID();
  const network = `xerxes-lab-${suffix}`;
  const fixture = `xerxes-fixture-${suffix}`;
  // Synthetic address exists only on the --internal lab bridge. No external route/ports are installed.
  const origin = 'http://11.253.248.10';
  const token = randomUUID();
  const defaults = loadConfig({});
  const config = { ...defaults, maxRequests: 100, scanTimeoutMs: 180_000, requestIntervalMs: 25,
    zap: { ...defaults.zap, timeoutMs: 180_000 },
    grants: [{ token, origin, modes: ['active' as const], expiresAt: new Date(Date.now() + 240_000).toISOString() }] };
  const controller = new AbortController();
  // Only the egress gateway's network is changed by this test-only Docker adapter. Production has no private-IP bypass.
  const docker: DockerRunner = (args, opts) => {
    const command = [...args];
    if (command[0] === 'run' && command.some((a) => a.startsWith('XERXES_GATEWAY_POLICY='))) command[command.indexOf('--network') + 1] = network;
    return runDocker(command, opts);
  };
  try {
    await runDocker(['image', 'inspect', config.zap.gatewayImage]);
    await runDocker(['network', 'create', '--internal', '--subnet', '11.253.248.0/24', network]);
    const application = "require('http').createServer((req,res)=>{const q=new URL(req.url,'http://fixture').searchParams.get('q')||'';res.writeHead(200,{'content-type':'text/html'});res.end('<html><body>'+q+'</body></html>')}).listen(80,'0.0.0.0')";
    await runDocker(['run', '-d', '--name', fixture, '--pull', 'never', '--network', network, '--ip', '11.253.248.10', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--sysctl', 'net.ipv4.ip_unprivileged_port_start=0', '--memory', '128m', '--pids-limit', '32', '--entrypoint', 'node', config.zap.gatewayImage, '-e', application]);
    const url = `${origin}/search?q=demo`;
    const result = await createZapBackend(config, docker)({ url, mode: 'active', authorizationToken: token },
      [{ url, status: 200, headers: { 'content-type': 'text/html' }, body: '<html><body>demo</body></html>' }], 100, controller.signal);
    assert.ok(result.findings.some((f) => f.checkId === 'zap-40012'), JSON.stringify(result.limitations));
  } finally {
    try { await runDocker(['rm', '-f', fixture]); } catch { /* Never remove unowned resources. */ }
    try { await runDocker(['network', 'rm', network]); } catch { /* Surface remaining lab names in test diagnostics if Docker is unavailable. */ }
  }
});
