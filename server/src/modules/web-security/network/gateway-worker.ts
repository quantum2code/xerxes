import { chmodSync } from 'node:fs';
import { loadConfig } from '../config.js';
import { createGateway, type GatewayPolicy } from './gateway.js';

// Dedicated Docker entry point. The only listener is a Unix socket on an ephemeral named volume.
const policy = JSON.parse(process.env.XERXES_GATEWAY_POLICY ?? 'null') as GatewayPolicy;
if (!policy) throw new Error('Gateway policy missing');
const config = loadConfig();
const { server, state } = createGateway(policy, config);
server.listen('/gateway/policy.sock', () => {
  chmodSync('/gateway/policy.sock', 0o666);
  if (process.getuid?.() === 0) { process.setgid!(1000); process.setuid!(1000); }
});
// State is retrieved over docker exec, not over an externally reachable administrative endpoint.
process.on('SIGUSR1', () => console.log(JSON.stringify(state)));
setTimeout(() => { server.closeAllConnections(); server.close(); }, Math.max(1, policy.expiresAt - Date.now())).unref();
