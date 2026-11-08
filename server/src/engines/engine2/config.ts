import { z } from 'zod';
import { grantSchema, type Engine2Config } from './types.js';

export function loadEngine2Config(env: NodeJS.ProcessEnv = process.env): Engine2Config {
  const int = (key: string, fallback: number, max: number) => {
    const parsed = z.coerce.number().int().min(1).max(max).safeParse(env[key] ?? fallback);
    if (!parsed.success) throw new Error(`Invalid ${key}`);
    return parsed.data;
  };
  const json = <T>(name: string, schema: z.ZodType<T>, fallback: T): T => {
    if (!env[name]) return fallback;
    try { return schema.parse(JSON.parse(env[name]!)); } catch { throw new Error(`Invalid ${name}`); }
  };
  const grants = json('ENGINE2_GRANTS', z.array(grantSchema).max(128), []);
  if (new Set(grants.map((g) => g.id)).size !== grants.length) throw new Error('Duplicate ENGINE2_GRANTS identifiers');
  return {
    enabled: env.ENGINE2_ENABLED === 'true', activeEnabled: env.ENGINE2_ACTIVE_ENABLED === 'true', grants,
    policies: json('ENGINE2_POLICIES', z.array(z.object({ name: z.string().regex(/^[\w-]{1,64}$/),
      ruleIds: z.array(z.string().regex(/^\d+$/)).min(1).max(32), strength: z.enum(['LOW', 'MEDIUM']), threshold: z.enum(['MEDIUM', 'HIGH']) })).min(1).max(16),
    [{ name: 'conservative', ruleIds: ['40012', '40018', '10028'], strength: 'LOW', threshold: 'MEDIUM' }]),
    totalTimeoutMs: int('ENGINE2_TOTAL_TIMEOUT_MS', 180000, 900000), startupTimeoutMs: int('ENGINE2_STARTUP_TIMEOUT_MS', 45000, 120000),
    spiderTimeoutMs: int('ENGINE2_SPIDER_TIMEOUT_MS', 45000, 300000), passiveTimeoutMs: int('ENGINE2_PASSIVE_TIMEOUT_MS', 30000, 300000),
    activeTimeoutMs: int('ENGINE2_ACTIVE_TIMEOUT_MS', 60000, 600000), apiTimeoutMs: int('ENGINE2_API_TIMEOUT_MS', 5000, 15000),
    requestTimeoutMs: int('ENGINE2_REQUEST_TIMEOUT_MS', 5000, 30000), pollIntervalMs: int('ENGINE2_POLL_INTERVAL_MS', 500, 5000),
    requestIntervalMs: int('ENGINE2_REQUEST_INTERVAL_MS', 250, 10000), maxRequests: int('ENGINE2_MAX_REQUESTS', 100, 1000),
    maxResponseBytes: int('ENGINE2_MAX_RESPONSE_BYTES', 1048576, 5242880), maxRequestBytes: 65536,
    maxDepth: int('ENGINE2_MAX_DEPTH', 3, 10), maxChildren: int('ENGINE2_MAX_CHILDREN', 10, 100),
    maxEndpoints: int('ENGINE2_MAX_ENDPOINTS', 100, 1000), maxActiveEndpoints: int('ENGINE2_MAX_ACTIVE_ENDPOINTS', 3, 20),
    maxFindings: int('ENGINE2_MAX_FINDINGS', 500, 1000), maxConcurrentScans: int('ENGINE2_MAX_CONCURRENT_SCANS', 2, 8),
    zapImage: env.ENGINE2_ZAP_IMAGE ?? 'ghcr.io/zaproxy/zaproxy:stable', gatewayImage: env.ENGINE2_GATEWAY_IMAGE ?? 'xerxes-engine2-gateway:local',
    labNetwork: env.ENGINE2_LAB_NETWORK ?? 'xerxes-engine2-lab', labTargetContainer: env.ENGINE2_LAB_TARGET ?? 'xerxes-engine2-fixture',
  };
}
