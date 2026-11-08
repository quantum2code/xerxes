// The ONLY file in this module that imports from another module. Everything network-safety related
// comes through here. When shared/network/policy.ts is on main, change these two lines and nothing else.
import { PolicyError } from '../web-security/network/policy.js';
export { PolicyError, resolvePublic, systemResolver, type Resolver } from '../web-security/network/policy.js';

const LOCAL_NAMES = /(?:^|\.)(?:localhost|local|internal|home|lan|test|invalid|onion)\.?$/i;

/** Strict target check for a TLS probe: https only, no credentials, port 443, no local-looking names. */
export function parseTlsTarget(raw: unknown): URL {
  if (typeof raw !== 'string' || raw.length > 4096 || /[\u0000-\u0020\u007f\\]/.test(raw)) throw new PolicyError('Invalid target URL');
  let url: URL;
  try { url = new URL(raw); } catch { throw new PolicyError('Invalid target URL'); }
  if (url.protocol !== 'https:' || url.username || url.password || !url.hostname || (url.port && url.port !== '443')) {
    throw new PolicyError('Only credential-free HTTPS URLs on port 443 are allowed');
  }
  if (LOCAL_NAMES.test(url.hostname) || url.hostname.endsWith('.')) throw new PolicyError('Prohibited hostname');
  return url;
}