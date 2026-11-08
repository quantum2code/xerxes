import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { authorize, parseTarget } from '../network/policy.js';
import { redact, safeUrl } from '../reporting/normalize.js';
import { owaspForCwe } from '../reporting/classify.js';
import type { BackendOutput, ZapBackend } from '../scanner.js';
import type { FindingInput, Page, ScannerConfig, Severity } from '../types.js';
import { runDocker, type DockerRunner } from './docker.js';

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
const apiClient = "import json,sys,urllib.request; print(urllib.request.urlopen(json.load(sys.stdin)['url'],timeout=5).read().decode('utf-8'))";

export function toHar(pages: Page[], origin?: string): string {
  return JSON.stringify({ log: { version: '1.2', creator: { name: 'Xerxes', version: '1.0' }, entries: pages.map((page) => {
    const url = new URL(page.url);
    const exported = origin ? new URL(url.pathname + url.search, origin).href : page.url;
    const headers = Object.entries(page.headers).flatMap(([name, raw]) => (Array.isArray(raw) ? raw : [raw]).map((value) => ({ name,
      value: /cookie|authorization|token|secret|key/i.test(name) ? (name.toLowerCase() === 'set-cookie' ? 'redacted=[REDACTED];' + value.split(';').slice(1).join(';') : '[REDACTED]') : redact(value) })));
    return { startedDateTime: new Date().toISOString(), time: 0,
      request: { method: 'GET', url: safeUrl(exported), httpVersion: 'HTTP/1.1', headers: [], queryString: [], cookies: [], headersSize: -1, bodySize: 0 },
      response: { status: page.status, statusText: '', httpVersion: 'HTTP/1.1', headers, cookies: [], content: { size: Buffer.byteLength(page.body), mimeType: String(page.headers['content-type'] ?? 'text/plain'), text: redact(page.body) }, redirectURL: '', headersSize: -1, bodySize: -1 },
      cache: {}, timings: { send: 0, wait: 0, receive: 0 } };
  }) } });
}

export function normalizeZapAlerts(raw: unknown, target: URL, proxyOrigin?: string): FindingInput[] {
  if (!Array.isArray(raw)) throw new Error('Malformed ZAP alerts');
  return raw.flatMap((alert): FindingInput[] => {
    if (!alert || typeof alert !== 'object' || String(alert.confidence) === '0') return [];
    const riskValue = alert.riskcode ?? alert.risk;
    const risk = /^\d$/.test(String(riskValue)) ? Number(riskValue) : ['informational', 'low', 'medium', 'high'].indexOf(String(riskValue).toLowerCase());
    const confidence = /^\d$/.test(String(alert.confidence)) ? Number(alert.confidence) : ['false positive', 'low', 'medium', 'high', 'confirmed'].indexOf(String(alert.confidence).toLowerCase());
    if (![0, 1, 2, 3].includes(risk) || ![1, 2, 3, 4].includes(confidence) || !/^\d+$/.test(String(alert.pluginId))) return [];
    let url: URL;
    try { url = parseTarget(alert.url); } catch { return []; }
    if (url.origin === proxyOrigin) url = new URL(url.pathname + url.search, target);
    if (url.origin !== target.origin) return [];
    const cwe = /^\d+$/.test(String(alert.cweid)) && Number(alert.cweid) > 0 ? `CWE-${alert.cweid}` : undefined;
    const param = typeof alert.param === 'string' && /^[\w.-]{1,64}$/.test(alert.param) ? alert.param : '[omitted]';
    // Do not copy arbitrary ZAP attack/evidence/otherInfo bodies: they may contain credential material.
    const markers = typeof alert.evidence === 'string' ? ['<script', 'SQL syntax', 'mysql', 'PostgreSQL', 'Location:'].filter((m) => alert.evidence.includes(m)) : [];
    return [{ checkId: `zap-${alert.pluginId}`, title: typeof alert.alert === 'string' ? alert.alert : 'ZAP security alert',
      description: 'OWASP ZAP reported this condition. Severity and confidence reflect the scanner, not independent exploit verification. Raw payloads and response excerpts are withheld to protect secrets.',
      severity: (['informational', 'low', 'medium', 'high'] as Severity[])[risk]!, confidence: confidence === 1 ? 'low' : confidence === 2 ? 'medium' : 'high',
      affectedUrl: url.href, evidence: [{ location: `ZAP rule ${alert.pluginId}; parameter ${param}`, observation: `ZAP alert ${/^\d+$/.test(String(alert.id)) ? alert.id : '[unavailable]'}; evidence markers: ${markers.join(', ') || 'raw content withheld'}; rescan this endpoint with the referenced rule to reproduce` }],
      cwe: cwe ? [cwe] : [], owasp: cwe ? owaspForCwe(cwe) : [], source: 'zap',
      remediation: `Review and remediate according to the rule documentation: https://www.zaproxy.org/docs/alerts/${alert.pluginId}/` }];
  });
}

export function createZapBackend(config: ScannerConfig, docker: DockerRunner = runDocker): ZapBackend {
  return async (request, pages, budget, parentSignal): Promise<BackendOutput> => {
    const target = parseTarget(request.url);
    const authorizationDeadline = authorize(request, target, config);
    const active = request.mode === 'active';
    if (active && budget < 1) return { status: 'blocked', findings: [], limitations: ['No remaining request budget for active ZAP assessment'] };
    const signal = AbortSignal.any([parentSignal, AbortSignal.timeout(config.zap.timeoutMs)]);
    try {
      if ((await docker(['info', '--format', '{{.OSType}}'], { signal })).trim() !== 'linux') throw new Error();
      await docker(['image', 'inspect', config.zap.image], { signal });
      if (active) await docker(['image', 'inspect', config.zap.gatewayImage], { signal });
    } catch { return { status: 'unavailable', findings: [], limitations: ['Docker Linux daemon or preinstalled ZAP/gateway image unavailable; no image is pulled automatically'] }; }
    const id = randomUUID();
    const name = `xerxes-zap-${id}`;
    const gateway = `xerxes-gateway-${id}`;
    const volume = `xerxes-policy-${id}`;
    const apiKey = randomUUID();
    const shadow = new URL(target.href); shadow.protocol = 'http:'; shadow.port = '';
    const created: string[] = [];
    let volumeCreated = false;
    let output: BackendOutput | undefined;
    const api = async (component: string, type: string, method: string, params: Record<string, string> = {}): Promise<Record<string, unknown>> => {
      const url = new URL(`http://127.0.0.1:8090/JSON/${component}/${type}/${method}/`);
      url.search = new URLSearchParams({ apikey: apiKey, ...params }).toString();
      const raw = await docker(['exec', '-i', name, 'python3', '-c', apiClient], { signal, input: JSON.stringify({ url: url.href }) });
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      if (parsed.code || parsed.error) throw new Error('ZAP API rejected operation');
      return parsed;
    };
    try {
      if (active) {
        await docker(['volume', 'create', '--label', `xerxes.web-security.scan=${id}`, volume], { signal }); volumeCreated = true;
        created.push(gateway);
        await docker(['run', '-d', '--name', gateway, '--label', `xerxes.web-security.scan=${id}`, '--pull', 'never', '--network', 'bridge', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '192m', '--cpus', '0.5', '--pids-limit', '64', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m', '--mount', `type=volume,source=${volume},target=/gateway`,
          '-e', `XERXES_GATEWAY_POLICY=${JSON.stringify({ origin: target.origin, proxyOrigin: shadow.origin, maxRequests: budget, expiresAt: Math.min(authorizationDeadline, Date.now() + Math.min(config.zap.timeoutMs - 100, config.scanTimeoutMs)) })}`,
          '-e', `WEB_SECURITY_MAX_REQUESTS=${config.maxRequests}`, '-e', `WEB_SECURITY_REQUEST_INTERVAL_MS=${config.requestIntervalMs}`, '-e', `WEB_SECURITY_REQUEST_TIMEOUT_MS=${config.requestTimeoutMs}`, '-e', `WEB_SECURITY_MAX_RESPONSE_BYTES=${config.maxResponseBytes}`, '-e', `WEB_SECURITY_ZAP_TIMEOUT_MS=${config.zap.timeoutMs}`, config.zap.gatewayImage], { signal });
      }
      created.push(name);
      await docker(['run', '-d', '--name', name, '--label', `xerxes.web-security.scan=${id}`, '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '1g', '--cpus', '1', '--pids-limit', '256', '--tmpfs', '/tmp:rw,nosuid,noexec,size=256m', '--tmpfs', '/home/zap:rw,nosuid,size=512m,uid=1000,gid=1000', '--tmpfs', '/zap/wrk:rw,noexec,nosuid,size=32m,uid=1000,gid=1000',
        ...(active ? ['--mount', `type=volume,source=${volume},target=/gateway,readonly`] : []), config.zap.image,
        'zap.sh', '-daemon', '-host', '127.0.0.1', '-port', '8090', '-silent', '-config', `api.key=${apiKey}`, '-config', 'api.disablekey=false',
        '-config', 'autoupdate.checkOnStart=false', '-config', 'autoupdate.downloadNewRelease=false', '-config', 'autoupdate.installAddonUpdates=false'], { signal });
      const inspection = JSON.parse(await docker(['inspect', name], { signal })) as { HostConfig: { NetworkMode: string; ReadonlyRootfs: boolean; CapDrop: string[]; SecurityOpt: string[] } }[];
      const host = inspection[0]?.HostConfig;
      if (!host || host.NetworkMode !== 'none' || !host.ReadonlyRootfs || !host.CapDrop.includes('ALL') || !host.SecurityOpt.includes('no-new-privileges')) throw new Error('Isolation verification failed');
      if (active) await docker(['exec', '-d', name, 'python3', '-c', relay], { signal });
      while (true) {
        signal.throwIfAborted();
        try { await api('core', 'view', 'version'); break; } catch { await delay(500, undefined, { signal }); }
      }
      await api('core', 'action', 'setMode', { mode: 'safe' });
      await api('pscan', 'action', 'setEnabled', { enabled: active ? 'false' : 'true' });
      await docker(['exec', '-i', name, 'python3', '-c', "import sys; open('/zap/wrk/input.har','w').write(sys.stdin.read())"], { signal, input: toHar(pages, active ? shadow.origin : undefined) });
      await api('exim', 'action', 'importHar', { filePath: '/zap/wrk/input.har' });
      let alerts: unknown;
      const limitations = ['ZAP uses an ephemeral, network-disabled Docker worker. Payloads and raw evidence are not included in reports.'];
      if (active) {
        await api('network', 'action', 'setHttpProxy', { host: '127.0.0.1', port: '8081' });
        await api('network', 'action', 'setHttpProxyEnabled', { enabled: 'true' });
        await api('network', 'action', 'setSocksProxyEnabled', { enabled: 'false' });
        const context = await api('context', 'action', 'newContext', { contextName: 'xerxes' });
        const escaped = shadow.origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        await api('context', 'action', 'includeInContext', { contextName: 'xerxes', regex: `^${escaped}/.*$` });
        await api('context', 'action', 'setContextInScope', { contextName: 'xerxes', booleanInScope: 'true' });
        await api('ascan', 'action', 'addScanPolicy', { scanPolicyName: 'xerxes', attackStrength: 'LOW', alertThreshold: 'MEDIUM' });
        await api('ascan', 'action', 'disableAllScanners', { scanPolicyName: 'xerxes' });
        await api('ascan', 'action', 'enableScanners', { ids: '40012,40018,10028', scanPolicyName: 'xerxes' });
        await api('ascan', 'action', 'setOptionThreadPerHost', { integer: '1' });
        await api('ascan', 'action', 'setOptionDelayInMs', { integer: String(config.requestIntervalMs) });
        await api('core', 'action', 'setMode', { mode: 'protect' });
        const scan = await api('ascan', 'action', 'scan', { url: shadow.href, recurse: 'false', inScopeOnly: 'true', scanPolicyName: 'xerxes', contextId: String(context.contextId) });
        if (!/^\d+$/.test(String(context.contextId)) || !/^\d+$/.test(String(scan.scan))) throw new Error('Malformed ZAP scan IDs');
        while (true) {
          const progress = Number((await api('ascan', 'view', 'status', { scanId: String(scan.scan) })).status);
          if (!Number.isInteger(progress) || progress < 0 || progress > 100) throw new Error('Malformed ZAP progress');
          if (progress === 100) break;
          await delay(250, undefined, { signal });
        }
        const ids = (await api('ascan', 'view', 'alertsIds', { scanId: String(scan.scan) })).alertsIds;
        if (!Array.isArray(ids) || ids.length > 1000) throw new Error('Invalid active alert IDs');
        alerts = [];
        for (const alertId of ids) (alerts as unknown[]).push((await api('alert', 'view', 'alert', { id: String(alertId) })).alert);
        limitations.push('Active rules: reflected XSS (40012), SQL injection (40018), open redirect (10028). Only the submitted endpoint is actively assessed; no recursive spider or OAST. Only GET/HEAD/POST/OPTIONS and content-type are forwarded.');
        if (target.protocol === 'https:') limitations.push('Active HTTPS uses an HTTP representation inside ZAP with certificate-verified HTTPS upstream. Secure-context/browser behavior is not assessed; passive shadow-transport alerts are excluded.');
      } else {
        while (true) {
          const pending = Number((await api('pscan', 'view', 'recordsToScan')).recordsToScan);
          if (!Number.isSafeInteger(pending) || pending < 0) throw new Error('Malformed passive scan progress');
          if (pending === 0) break;
          await delay(250, undefined, { signal });
        }
        alerts = (await api('alert', 'view', 'alerts', { start: '0', count: '1000' })).alerts;
        limitations.push('Passive ZAP analyzes redacted HAR captured by the native safe transport, with no additional target requests. Redaction may suppress some detections.');
      }
      let status: BackendOutput['status'] = 'completed';
      if (active) {
        await docker(['kill', '--signal', 'USR1', gateway], { signal });
        await delay(100, undefined, { signal });
        // The gateway logs only structured counters. Any denial/failure means incomplete coverage.
        const logs = await docker(['logs', gateway], { signal });
        const state = JSON.parse(logs.trim().split(/\r?\n/).at(-1) ?? '{}') as { exhausted?: boolean; denied?: number; failures?: number; forwarded?: number };
        if (state.exhausted || state.denied || state.failures || !state.forwarded) { status = 'failed'; limitations.push('Gateway blocked requests, reached a budget, or saw upstream failures; active coverage is incomplete'); }
      }
      if (Array.isArray(alerts) && alerts.length >= 1000) { status = 'failed'; limitations.push('ZAP alert collection limit reached; output may be truncated'); }
      output = { status, findings: normalizeZapAlerts(alerts, target, active ? shadow.origin : undefined), limitations };
      return output;
    } catch {
      output = { status: signal.aborted ? 'failed' : 'blocked', findings: [], limitations: ['ZAP did not finish or sandbox/API validation failed; no complete active coverage can be claimed'] };
      return output;
    }
    finally {
      // Cleanup must run even after cancellation. Names are random and belong exclusively to this scan.
      let cleanupFailed = false;
      for (const container of created.reverse()) { try { await docker(['rm', '-f', container], { timeoutMs: 10_000 }); } catch { cleanupFailed = true; } }
      if (volumeCreated) { try { await docker(['volume', 'rm', volume], { timeoutMs: 10_000 }); } catch { cleanupFailed = true; } }
      if (cleanupFailed && output) {
        output.status = 'failed';
        output.limitations.push(`Docker cleanup incomplete; operator must inspect resources labeled xerxes.web-security.scan=${id}`);
      }
    }
  };
}
