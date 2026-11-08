import { safeUrl } from '../../../shared/security/redaction.js';

/** Query values and fragments are never exposed, including duplicate parameters. Not a fetch target. */
export function reportUrl(raw: string, preserveOriginal = false): string {
  const url = new URL(raw);
  const query = new URLSearchParams();
  for (const [name] of url.searchParams) query.append(name, '[REDACTED]');
  const base = new URL(url.href); base.search = ''; base.hash = '';
  const safeBase = safeUrl(base.href);
  const rawBase = raw.split(/[?#]/, 1)[0]!;
  return (preserveOriginal && safeBase === base.href ? rawBase : safeBase) + (query.size ? `?${query}` : '');
}
