import { chmodSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { z } from 'zod';
import { loadEngine2Config } from '../config.js';
import { scopeRulesSchema } from '../types.js';
import { createPolicyGateway } from './gateway.js';
import { normalizedRules } from '../scope/rules.js';

// Container-only entry point. Controller supplies policy; no request can change it or the phase file.
const policySchema = z.object({ rules: scopeRulesSchema, mode: z.enum(['passive', 'active']), expiresAt: z.number().int().positive(), labAddresses: z.array(z.string()).max(16) });
let policy: z.infer<typeof policySchema>;
try { policy = policySchema.parse(JSON.parse(process.env.ENGINE2_GATEWAY_POLICY ?? 'null')); }
catch { throw new Error('Invalid gateway policy'); }
policy.rules = normalizedRules(policy.rules);
if (policy.expiresAt <= Date.now() || policy.expiresAt > Date.now() + 900000) throw new Error('Invalid gateway deadline');
const config = loadEngine2Config();
const phaseSchema = z.object({ mode: z.enum(['idle', 'crawl', 'active']), expiresAt: z.number().nonnegative() });
const gateway = await createPolicyGateway(policy, config, { phase: () => {
  try { return phaseSchema.parse(JSON.parse(readFileSync('/tmp/engine2-phase', 'utf8'))); } catch { return { mode: 'idle', expiresAt: 0 }; }
}, onStatistics: (stats) => {
  writeFileSync('/tmp/engine2-stats.next', JSON.stringify(stats), { mode: 0o600 }); renameSync('/tmp/engine2-stats.next', '/tmp/engine2-stats.json');
} });
writeFileSync('/gateway/ca.pem', gateway.certificate, { mode: 0o644 });
gateway.server.listen('/gateway/policy.sock', () => {
  chmodSync('/gateway/policy.sock', 0o666);
  writeFileSync('/tmp/engine2-phase', '{"mode":"idle","expiresAt":0}', { mode: 0o600 });
  writeFileSync('/tmp/engine2-stats.json', JSON.stringify(gateway.stats), { mode: 0o600 });
});
// No target strings or response data in worker logs. Stats update atomically on every change.
const expiry = setTimeout(async () => { await gateway.close(); }, Math.max(1, policy.expiresAt - Date.now()));
process.on('SIGTERM', async () => { clearTimeout(expiry); await gateway.close(); });
