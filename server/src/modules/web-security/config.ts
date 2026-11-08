import type { ScannerConfig } from './types.js';

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ScannerConfig {
  const integer = (name: string, fallback: number, max: number): number => {
    if (env[name] === undefined) return fallback;
    const value = Number(env[name]);
    if (!Number.isSafeInteger(value) || value < 1 || value > max) throw new Error(`Invalid ${name}`);
    return value;
  };
  let grants: ScannerConfig['grants'] = [];
  if (env.WEB_SECURITY_GRANTS) {
    let parsed: unknown;
    try { parsed = JSON.parse(env.WEB_SECURITY_GRANTS); }
    catch { throw new Error('Invalid WEB_SECURITY_GRANTS JSON'); }
    if (!Array.isArray(parsed) || parsed.some((g) => !g || typeof g.token !== 'string' || g.token.length < 32 ||
      typeof g.origin !== 'string' || !Array.isArray(g.modes) || g.modes.length === 0 ||
      g.modes.some((m: unknown) => m !== 'passive' && m !== 'active') || !Number.isFinite(Date.parse(g.expiresAt)))) {
      throw new Error('Invalid WEB_SECURITY_GRANTS');
    }
    grants = parsed;
    for (const grant of grants) {
      let url: URL;
      try { url = new URL(grant.origin); }
      catch { throw new Error('Invalid WEB_SECURITY_GRANTS origin'); }
      if (!['http:', 'https:'].includes(url.protocol) || url.origin !== grant.origin || url.username || url.password) {
        throw new Error('Authorization grants must specify exact HTTP(S) origins');
      }
    }
  }
  return {
    requestTimeoutMs: integer('WEB_SECURITY_REQUEST_TIMEOUT_MS', 5_000, 30_000),
    scanTimeoutMs: integer('WEB_SECURITY_SCAN_TIMEOUT_MS', 30_000, 300_000),
    maxResponseBytes: integer('WEB_SECURITY_MAX_RESPONSE_BYTES', 1_048_576, 5_242_880),
    maxRequests: integer('WEB_SECURITY_MAX_REQUESTS', 10, 100),
    maxRedirects: integer('WEB_SECURITY_MAX_REDIRECTS', 3, 10),
    maxDepth: 1,
    requestIntervalMs: integer('WEB_SECURITY_REQUEST_INTERVAL_MS', 250, 10_000),
    maxConcurrentScans: integer('WEB_SECURITY_MAX_CONCURRENT_SCANS', 4, 32),
    grants,
    requirePassiveAuthorization: env.WEB_SECURITY_REQUIRE_PASSIVE_AUTH !== 'false',
    zap: {
      enabled: env.WEB_SECURITY_ZAP_ENABLED === 'true',
      image: env.WEB_SECURITY_ZAP_IMAGE ?? 'ghcr.io/zaproxy/zaproxy:stable',
      gatewayImage: env.WEB_SECURITY_GATEWAY_IMAGE ?? 'xerxes-web-security-gateway:local',
      timeoutMs: integer('WEB_SECURITY_ZAP_TIMEOUT_MS', 120_000, 300_000),
    },
  };
}
