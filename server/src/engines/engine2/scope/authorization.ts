import { createHash, timingSafeEqual } from 'node:crypto';
import { Engine2Failure } from '../errors.js';
import type { AuthorizationGrant, Engine2Config, Engine2ScanRequest } from '../types.js';

export function verifyAuthorization(request: Engine2ScanRequest, config: Engine2Config): AuthorizationGrant {
  const provided = createHash('sha256').update(request.authorizationToken).digest();
  const grant = config.grants.find((g) => g.id === request.authorizationId);
  if (!grant || !timingSafeEqual(provided, Buffer.from(grant.tokenSha256, 'hex')) || Date.parse(grant.expiresAt) <= Date.now()) throw new Engine2Failure('UNAUTHORIZED', 'Missing, invalid, revoked or expired target authorization');
  if (request.mode === 'active') {
    if (!config.activeEnabled) throw new Engine2Failure('ACTIVE_DISABLED', 'Active testing is disabled');
    const proof = grant.activeVerification;
    if (!proof || Date.parse(proof.verifiedAt) > Date.now() || !proof.verifiedBy || !proof.evidenceRef) throw new Engine2Failure('ACTIVE_NOT_VERIFIED', 'Active testing requires a server-provisioned verified approval');
    if (!grant.allowedPolicies.includes(request.policy) || !config.policies.some((p) => p.name === request.policy)) throw new Engine2Failure('POLICY_NOT_AUTHORIZED', 'Scan policy not authorized for this grant');
  }
  return grant;
}
