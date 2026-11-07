import { parse } from 'tldts';
export const redirectStatuses = new Set([301, 302, 303, 307, 308]);
export function crossesDomain(source: URL, target: URL): boolean | null {
  const a = parse(source.hostname, { allowPrivateDomains: true }).domain;
  const b = parse(target.hostname, { allowPrivateDomains: true }).domain;
  return a && b ? a !== b : null;
}
