import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';
import { runDocker, type DockerRunner } from '../../../modules/web-security/integrations/docker.js';
import { Semaphore } from '../../../shared/network/limits.js';
import { Engine2Failure } from '../errors.js';
import { ApprovedScope } from '../scope/validator.js';
import type { Engine2Config } from '../types.js';
import { ZapClient, type ZapTransport } from './client.js';
import { createContext } from './context.js';
import { waitForZap } from './health.js';
import { verifyLab } from './lab.js';
import type { GatewayStatistics, JobFactory, ZapJob } from './job.js';

// Fixed transport plumbing inside the existing ZAP image; not a Python analysis service.
const relay = `import socket,socketserver,select
class Relay(socketserver.BaseRequestHandler):
 def handle(self):
  peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
  try:
   peer.connect('/gateway/policy.sock')
   while True:
    ready,_,_=select.select([self.request,peer],[],[],30)
    if not ready: break
    for source in ready:
     data=source.recv(65536)
     if not data: return
     (peer if source is self.request else self.request).sendall(data)
  finally: peer.close()
class Server(socketserver.ThreadingTCPServer):
 allow_reuse_address=True
 daemon_threads=True
Server(('127.0.0.1',8081),Relay).serve_forever()`;
const apiScript = `import json,sys,urllib.request,urllib.parse
data=json.load(sys.stdin)
url='http://127.0.0.1:8090/JSON/'+data['component']+'/'+data['kind']+'/'+data['name']+'/?'+urllib.parse.urlencode(data['params'])
req=urllib.request.Request(url,headers={'X-ZAP-API-Key':data['apiKey']})
with urllib.request.urlopen(req,timeout=data['timeout']) as response:
 body=response.read(5242881)
 if len(body)>5242880: raise ValueError('API response limit')
 sys.stdout.write(body.decode('utf-8'))`;
const hostSchema = z.object({ NetworkMode: z.string(), ReadonlyRootfs: z.literal(true), Privileged: z.literal(false), CapDrop: z.array(z.string()),
  SecurityOpt: z.array(z.string()), PortBindings: z.record(z.string(), z.unknown()).nullable() });
const inspectionSchema = z.array(z.object({ HostConfig: hostSchema,
  Config: z.object({ User: z.literal('1000:1000') }),
  NetworkSettings: z.object({ Networks: z.record(z.string(), z.object({ NetworkID: z.string() })) }),
  Mounts: z.array(z.object({ Type: z.string(), Name: z.string().optional(), Destination: z.string(), RW: z.boolean() })) })).length(1);
const statisticsSchema = z.object({ forwarded: z.number().int().nonnegative(), denied: z.number().int().nonnegative(), failures: z.number().int().nonnegative(), exhausted: z.boolean() });

export function createDockerJobFactory(config: Engine2Config, docker: DockerRunner = runDocker): JobFactory {
  return async (scope, parent) => {
    ApprovedScope.assert(scope);
    try {
      if ((await docker(['info', '--format', '{{.OSType}}'], { signal: parent })).trim() !== 'linux') throw new Error();
      await docker(['image', 'inspect', config.zapImage], { signal: parent });
      await docker(['image', 'inspect', config.gatewayImage], { signal: parent });
    } catch { throw new Engine2Failure('ZAP_UNAVAILABLE', 'Linux Docker daemon or preinstalled ZAP/gateway image unavailable'); }
    const id = randomUUID(); const zap = `xerxes-engine2-zap-${id}`; const gateway = `xerxes-engine2-gateway-${id}`; const volume = `xerxes-engine2-policy-${id}`;
    const apiKey = randomUUID(); const label = `xerxes.engine2.job=${id}`;
    const expiresAt = Math.min(scope.expiresAt, Date.now() + config.totalTimeoutMs);
    const signal = AbortSignal.any([parent, AbortSignal.timeout(Math.max(1, expiresAt - Date.now()))]);
    const containers: string[] = []; let volumeCreated = false; let closed = false; let cleaning: Promise<void> | null = null;
    const cleanup = (): Promise<void> => {
      closed = true;
      if (cleaning) return cleaning;
      cleaning = (async () => {
        for (const name of [...containers].reverse()) try {
          await docker(['rm', '-f', name], { timeoutMs: 10000 }); containers.splice(containers.indexOf(name), 1);
        } catch { /* Keep failed resources for a later close attempt. */ }
        if (volumeCreated && !containers.length) try { await docker(['volume', 'rm', volume], { timeoutMs: 10000 }); volumeCreated = false; } catch { /* Retryable cleanup. */ }
        if (containers.length || volumeCreated) throw new Engine2Failure('CLEANUP_FAILED', `Inspect only resources labelled ${label}; Docker cleanup was incomplete`);
      })().finally(() => { cleaning = null; });
      return cleaning;
    };
    try {
      let network = 'bridge';
      if (scope.rules.profile === 'isolated-lab') {
        const lab = await verifyLab(config, docker, signal);
        if (lab.networkId !== scope.lab?.networkId || JSON.stringify(lab.addresses) !== JSON.stringify(scope.lab.addresses) || lab.hostname !== scope.lab.hostname) throw new Engine2Failure('LAB_CHANGED', 'Development network changed since scope approval');
        network = config.labNetwork;
      }
      // tmpfs local volume is owned by the unprivileged workers from the outset: no setuid/chown capabilities.
      await docker(['volume', 'create', '--label', label, '--driver', 'local', '--opt', 'type=tmpfs', '--opt', 'device=tmpfs', '--opt', 'o=size=16m,uid=1000,gid=1000,mode=0770,nosuid,noexec', volume], { signal }); volumeCreated = true;
      containers.push(gateway);
      await docker(['run', '-d', '--name', gateway, '--label', label, '--pull', 'never', '--user', '1000:1000', '--network', network, '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '256m', '--cpus', '1', '--pids-limit', '64', '--tmpfs', '/tmp:rw,nosuid,noexec,size=16m',
        '--mount', `type=volume,source=${volume},target=/gateway`, '--health-cmd', 'node -e "process.exit(require(\'fs\').existsSync(\'/gateway/policy.sock\')?0:1)"', '--health-interval', '5s', '--health-timeout', '3s', '--health-retries', '3',
        '-e', `ENGINE2_GATEWAY_POLICY=${JSON.stringify({ rules: scope.rules, mode: scope.request.mode, expiresAt, labAddresses: scope.lab?.addresses ?? [] })}`,
        '-e', `ENGINE2_MAX_REQUESTS=${config.maxRequests}`, '-e', `ENGINE2_MAX_RESPONSE_BYTES=${config.maxResponseBytes}`,
        '-e', `ENGINE2_REQUEST_TIMEOUT_MS=${config.requestTimeoutMs}`, '-e', `ENGINE2_REQUEST_INTERVAL_MS=${config.requestIntervalMs}`, config.gatewayImage], { signal });
      const gatewayInspection = inspectionSchema.parse(JSON.parse(await docker(['inspect', gateway], { signal })))[0]!;
      const assertSandbox = (value: typeof gatewayInspection) => {
        if (!value.HostConfig.CapDrop.includes('ALL') || !value.HostConfig.SecurityOpt.some((s) => s.split(':')[0] === 'no-new-privileges') || Object.keys(value.HostConfig.PortBindings ?? {}).length) throw new Engine2Failure('ISOLATION_FAILED', 'Required container isolation unavailable');
      };
      assertSandbox(gatewayInspection);
      if (gatewayInspection.HostConfig.NetworkMode !== network || Object.keys(gatewayInspection.NetworkSettings.Networks).length !== 1 ||
          scope.lab && gatewayInspection.NetworkSettings.Networks[network]?.NetworkID !== scope.lab.networkId ||
          gatewayInspection.Mounts.length !== 1 || gatewayInspection.Mounts[0]?.Name !== volume || gatewayInspection.Mounts[0]?.Destination !== '/gateway') throw new Engine2Failure('ISOLATION_FAILED', 'Gateway network/volume isolation mismatch');
      const startup = AbortSignal.any([signal, AbortSignal.timeout(config.startupTimeoutMs)]);
      while (true) {
        startup.throwIfAborted();
        try { await docker(['exec', gateway, 'node', '-e', "const fs=require('fs'); if(!fs.existsSync('/gateway/policy.sock')||!fs.existsSync('/gateway/ca.pem')||!fs.existsSync('/tmp/engine2-phase'))process.exit(1)"], { signal: startup }); break; }
        catch { await delay(100, undefined, { signal: startup }); }
      }
      containers.push(zap);
      const bootstrap = 'umask 077; keytool -importcert -noprompt -alias engine2-gateway -file /gateway/ca.pem -keystore /tmp/engine2-trust.p12 -storetype PKCS12 -storepass changeit >/dev/null 2>&1 || exit 1; exec zap.sh "$@"';
      const health = 'python3 -c "import os,urllib.request; urllib.request.urlopen(urllib.request.Request(\'http://127.0.0.1:8090/JSON/core/view/version/\',headers={\'X-ZAP-API-Key\':os.environ[\'ENGINE2_ZAP_API_KEY\']}),timeout=3).read()"';
      await docker(['run', '-d', '--name', zap, '--label', label, '--pull', 'never', '--user', '1000:1000', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '1g', '--cpus', '1', '--pids-limit', '256',
        '--tmpfs', '/tmp:rw,nosuid,size=256m', '--tmpfs', '/home/zap:rw,nosuid,size=512m,uid=1000,gid=1000', '--tmpfs', '/zap/wrk:rw,nosuid,noexec,size=32m,uid=1000,gid=1000',
        '--mount', `type=volume,source=${volume},target=/gateway,readonly`, '--health-cmd', health, '--health-interval', '5s', '--health-timeout', '5s', '--health-start-period', '30s', '--health-retries', '3',
        '-e', `ENGINE2_ZAP_API_KEY=${apiKey}`, '-e', 'JAVA_OPTS=-Xmx512m -Djavax.net.ssl.trustStore=/tmp/engine2-trust.p12 -Djavax.net.ssl.trustStorePassword=changeit',
        '--entrypoint', 'sh', config.zapImage, '-c', bootstrap, '--', '-daemon', '-host', '127.0.0.1', '-port', '8090', '-silent', '-config', `api.key=${apiKey}`, '-config', 'api.disablekey=false',
        '-config', 'autoupdate.checkOnStart=false', '-config', 'autoupdate.downloadNewRelease=false', '-config', 'autoupdate.installAddonUpdates=false'], { signal });
      const zapInspection = inspectionSchema.parse(JSON.parse(await docker(['inspect', zap], { signal })))[0]!;
      assertSandbox(zapInspection);
      if (zapInspection.HostConfig.NetworkMode !== 'none' || zapInspection.Mounts.length !== 1 || zapInspection.Mounts[0]?.Name !== volume || zapInspection.Mounts[0]?.RW !== false) throw new Engine2Failure('ISOLATION_FAILED', 'ZAP must have network disabled and a read-only policy socket volume');
      await docker(['exec', '-d', zap, 'python3', '-c', relay], { signal });
      const transport: ZapTransport = async (req, callSignal) => {
        if (!/^[a-zA-Z0-9]+$/.test(req.component) || !/^[a-zA-Z0-9]+$/.test(req.name)) throw new Engine2Failure('API_OPERATION_INVALID', 'Invalid management operation');
        return JSON.parse(await docker(['exec', '-i', zap, 'python3', '-c', apiScript], { signal: callSignal, timeoutMs: config.apiTimeoutMs + 1000,
          input: JSON.stringify({ ...req, apiKey, timeout: config.apiTimeoutMs / 1000 }) }));
      };
      const client = new ZapClient(transport, config.apiTimeoutMs);
      await waitForZap(client, config.startupTimeoutMs, signal);
      await client.action('network', 'setHttpProxy', { host: '127.0.0.1', port: '8081' }, signal);
      await client.action('network', 'setHttpProxyEnabled', { enabled: 'true' }, signal);
      await client.action('network', 'setSocksProxyEnabled', { enabled: 'false' }, signal);
      const contextId = await createContext(client, scope, signal);
      const lock = new Semaphore(1); const endpoints = new Set<string>();
      const job: ZapJob = { id, scope, client, contextId, config, passiveConfigured: false,
        async enterPhase(phase, callSignal) {
          if (phase === 'active') ApprovedScope.assert(scope);
          if (phase === 'active' && (scope.request.mode !== 'active' || !config.activeEnabled)) throw new Engine2Failure('ACTIVE_NOT_AUTHORIZED', 'This job is not authorized for active testing');
          const deadline = phase === 'idle' ? 0 : Math.min(expiresAt, Date.now() + (phase === 'active' ? config.activeTimeoutMs : config.spiderTimeoutMs));
          await docker(['exec', '--user', '1000:1000', '-i', gateway, 'node', '-e', "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{const p=JSON.parse(s);if(!['idle','crawl','active'].includes(p.mode)||!Number.isFinite(p.expiresAt))process.exit(1);const fs=require('fs');fs.writeFileSync('/tmp/engine2-phase.next',s,{mode:0o600});fs.renameSync('/tmp/engine2-phase.next','/tmp/engine2-phase')})"], { signal: callSignal, input: JSON.stringify({ mode: phase, expiresAt: deadline }) });
        },
        async statistics(callSignal): Promise<GatewayStatistics> {
          return statisticsSchema.parse(JSON.parse(await docker(['exec', '--user', '1000:1000', gateway, 'node', '-e', "process.stdout.write(require('fs').readFileSync('/tmp/engine2-stats.json','utf8'))"], { signal: callSignal })));
        },
        exclusive: (callSignal, operation) => lock.run(callSignal, async () => {
          if (closed) throw new Engine2Failure('JOB_CLOSED', 'ZAP job is already closed');
          return operation();
        }),
        recordEndpoints(urls) { for (const url of urls) if (endpoints.size < config.maxEndpoints && scope.includes(url).allowed) endpoints.add(new URL(url).href); },
        endpoints: () => [...endpoints], close: cleanup, toJSON: () => ({ jobId: id, scopeId: scope.id }),
      };
      return job;
    } catch (error) { await cleanup(); throw error; }
  };
}
