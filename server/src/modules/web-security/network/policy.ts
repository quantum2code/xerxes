import { timingSafeEqual } from 'node:crypto';
import type { ScannerConfig, ScanRequest } from '../types.js';
import { PolicyError } from '../../../shared/network/policy.js';
export { PolicyError, publicAddress, resolvePublic, systemResolver, type Resolver } from '../../../shared/network/policy.js';

export function parseTarget(raw: unknown): URL {
  if (typeof raw !== 'string' || raw.length > 4096 || /[\u0000-\u0020\u007f\\]/.test(raw)) throw new PolicyError('Invalid target URL');
  let url: URL;
  try { url = new URL(raw); } catch { throw new PolicyError('Invalid target URL'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || !url.hostname || url.hash ||
      (url.port && !['80', '443'].includes(url.port))) throw new PolicyError('Only credential-free HTTP(S) URLs on ports 80/443 are allowed');
  // Avoid ambiguous zone IDs and local discovery names even before resolution.
  if (/(?:^|\.)(?:localhost|local|internal|home|lan|test|invalid|onion)\.?$/i.test(url.hostname) || url.hostname.endsWith('.')) {
    throw new PolicyError('Prohibited hostname');
  }
  return url;
}
export function authorize(request: ScanRequest, url: URL, config: ScannerConfig): number {
  if (request.mode !== undefined && request.mode !== 'passive' && request.mode !== 'active') throw new PolicyError('Invalid scan mode');
  if ((request.mode ?? 'passive') === 'passive' && !config.requirePassiveAuthorization) return Infinity;
  const token = typeof request.authorizationToken === 'string' ? request.authorizationToken : '';
  const supplied = Buffer.from(token);
  const grant = config.grants.find((candidate) => {
    const expected = Buffer.from(candidate.token);
    return supplied.length === expected.length && timingSafeEqual(supplied, expected) && candidate.origin === url.origin &&
      candidate.modes.includes(request.mode ?? 'passive') && Date.parse(candidate.expiresAt) > Date.now();
  });
  if (!grant) throw new PolicyError('A valid, unexpired authorization grant for this exact origin and mode is required');
  return Date.parse(grant.expiresAt);
}
