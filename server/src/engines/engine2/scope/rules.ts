import { isIP } from 'node:net';
import { parse as parseDomain } from 'tldts';
import { scopeRulesSchema, type ScopeRules } from '../types.js';
import { Engine2Failure } from '../errors.js';

export function scopeUrl(raw: string): URL {
  if (raw.length > 4096 || !/^https?:\/\//i.test(raw) || /[\u0000-\u0020\u007f\\]/.test(raw)) throw new Engine2Failure('INVALID_URL', 'Only unambiguous HTTP(S) targets are accepted');
  let url: URL;
  try { url = new URL(raw); } catch { throw new Engine2Failure('INVALID_URL', 'Invalid target URL'); }
  if (url.username || url.password || raw.slice(raw.indexOf('://') + 3).split(/[/?#]/, 1)[0]!.includes('@') || !url.hostname || raw.includes('#')) throw new Engine2Failure('INVALID_URL', 'Credentials and fragments are not accepted');
  canonicalPath(url.pathname); return url;
}
export function canonicalPath(path: string): string {
  if (!path.startsWith('/') || /%2f|%5c|%25|%00/i.test(path)) throw new Engine2Failure('AMBIGUOUS_PATH', 'Ambiguous encoded path rejected');
  let decoded: string;
  try { decoded = decodeURIComponent(path); } catch { throw new Engine2Failure('AMBIGUOUS_PATH', 'Malformed encoded path'); }
  if (decoded.normalize('NFKC') !== decoded || /[\u0000-\u0020\u007f\\?#;]/.test(decoded) || decoded.includes('//') || decoded.split('/').some((s) => s === '.' || s === '..')) throw new Engine2Failure('AMBIGUOUS_PATH', 'Noncanonical path rejected');
  return decoded === '/' ? '/' : decoded.replace(/\/$/, '');
}
export function normalizedRules(raw: ScopeRules): ScopeRules {
  const rules = scopeRulesSchema.parse(raw);
  rules.hosts = rules.hosts.map((host) => {
    if (!isIP(host.hostname.replace(/^\[|\]$/g, '')) && /[:/?#@\\]/.test(host.hostname)) throw new Engine2Failure('INVALID_SCOPE', 'Hosts must not contain URL components');
    const url = new URL(`https://${isIP(host.hostname) === 6 ? `[${host.hostname}]` : host.hostname}`);
    if (url.host !== url.hostname || url.pathname !== '/' || url.search || url.hash || url.username || url.password || url.hostname.endsWith('.')) throw new Engine2Failure('INVALID_SCOPE', 'Invalid allowlisted hostname');
    const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (host.includeSubdomains && isIP(hostname)) throw new Engine2Failure('INVALID_SCOPE', 'IP scopes cannot include subdomains');
    if (host.includeSubdomains) {
      const suffix = parseDomain(hostname, { allowPrivateDomains: true });
      if (!suffix.domain || !suffix.isIcann && !suffix.isPrivate) throw new Engine2Failure('INVALID_SCOPE', 'Subdomain permissions require a registrable base domain, not a public or unknown suffix');
    }
    return { hostname, includeSubdomains: host.includeSubdomains };
  });
  rules.paths = rules.paths.map(canonicalPath); rules.excludedPaths = rules.excludedPaths.map(canonicalPath);
  return rules;
}
export interface ScopeDecision { allowed: boolean; reason: string | null; }
const boundary = (path: string, base: string) => base === '/' || path === base || path.startsWith(`${base}/`);
export function checkScope(raw: string | URL, rules: ScopeRules): ScopeDecision {
  try {
    const url = scopeUrl(typeof raw === 'string' ? raw : raw.href);
    const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (!rules.hosts.some((h) => host === h.hostname || (h.includeSubdomains && host.endsWith(`.${h.hostname}`)))) return { allowed: false, reason: 'HOST_OUT_OF_SCOPE' };
    if (!rules.protocols.includes(url.protocol as 'http:' | 'https:') || !rules.ports.includes(Number(url.port || (url.protocol === 'https:' ? 443 : 80)))) return { allowed: false, reason: 'PROTOCOL_OR_PORT_OUT_OF_SCOPE' };
    const path = canonicalPath(url.pathname);
    if (!rules.paths.some((p) => boundary(path, p))) return { allowed: false, reason: 'PATH_OUT_OF_SCOPE' };
    if (rules.excludedPaths.some((p) => boundary(path, p))) return { allowed: false, reason: 'EXCLUDED_PATH' };
    // Default destructive endpoint guard applies at any depth, not just the scope root.
    if (/(?:^|\/)(?:logout|signout|delete|remove|delete-account|checkout|purchase|payment)(?:\/|$)/i.test(path)) return { allowed: false, reason: 'SENSITIVE_ENDPOINT' };
    return { allowed: true, reason: null };
  } catch { return { allowed: false, reason: 'INVALID_OR_AMBIGUOUS_URL' }; }
}
