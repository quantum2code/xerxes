import { parse } from 'tldts';
export const redirectStatuses = new Set([301, 302, 303, 307, 308]);
export function crossesDomain(source: URL, target: URL): boolean | null {
  const registrable = (url: URL) => {
    const result = parse(url.hostname, { allowPrivateDomains: true });
    return result.isIcann || result.isPrivate ? result.domain : null;
  };
  const a = registrable(source);
  const b = registrable(target);
  return a && b ? a !== b : null;
}
