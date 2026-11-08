import { createHash, randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Only provisions the fixed internal fixture, never arbitrary private-network targets.
const active = process.argv.includes('--active');
const token = randomBytes(32).toString('hex');
const grant = {
  id: 'engine2-lab', tokenSha256: createHash('sha256').update(token).digest('hex'),
  expiresAt: new Date(Date.now() + 3600000).toISOString(), crawlAuthorized: true,
  rules: {
    hosts: [{ hostname: 'xerxes-engine2-fixture', includeSubdomains: false }], protocols: ['http:'], ports: [8080],
    paths: ['/app'], excludedPaths: ['/app/private'], activeMethods: ['GET', 'HEAD'], profile: 'isolated-lab',
  },
  allowedPolicies: ['conservative'],
  ...(active ? { activeVerification: { verifiedBy: 'local-fixture-operator', evidenceRef: 'docker/engine2/compose.yaml', verifiedAt: new Date().toISOString() } } : {}),
};
const destination = fileURLToPath(new URL('../../.env.engine2.local', import.meta.url));
writeFileSync(destination, `ENGINE2_ENABLED=true\nENGINE2_ACTIVE_ENABLED=${active}\nENGINE2_GRANTS=${JSON.stringify([grant])}\n`, { mode: 0o600, flag: 'wx' });
console.log(`Created ${destination} (expires in one hour). Existing files are never overwritten.`);
console.log(`Authorization ID: ${grant.id}\nAuthorization token (keep private): ${token}`);
