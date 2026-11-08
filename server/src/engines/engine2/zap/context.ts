import { z } from 'zod';
import { ApprovedScope } from '../scope/validator.js';
import { ZapClient, idSchema } from './client.js';

const escaped = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
export function contextPatterns(scope: ApprovedScope): { includes: string[]; excludes: string[] } {
  ApprovedScope.assert(scope);
  const rules = scope.rules;
  const authorities = rules.hosts.map((host) => `${host.includeSubdomains ? '(?:[a-zA-Z0-9-]+\\.)*' : ''}${escaped(host.hostname.includes(':') ? `[${host.hostname}]` : host.hostname)}`);
  const prefixes = rules.protocols.flatMap((protocol) => authorities.flatMap((host) => rules.ports.map((port) => {
    const defaultPort = protocol === 'https:' ? 443 : 80;
    return `${escaped(protocol)}//${host}${port === defaultPort ? `(?::${port})?` : `:${port}`}`;
  })));
  const pathPattern = (path: string) => path === '/' ? '/[^#]*' : `${escaped(path)}(?:/[^#?]*)?(?:\\?[^#]*)?`;
  return {
    includes: prefixes.flatMap((p) => rules.paths.map((path) => `^${p}${pathPattern(path)}$`)),
    excludes: prefixes.flatMap((p) => rules.excludedPaths.map((path) => `^${p}${pathPattern(path)}$`)),
  };
}
export async function createContext(client: ZapClient, scope: ApprovedScope, signal: AbortSignal): Promise<string> {
  ApprovedScope.assert(scope);
  const name = `engine2-${scope.id}`;
  const context = await client.call('context', 'action', 'newContext', { contextName: name }, z.object({ contextId: idSchema }), signal);
  const patterns = contextPatterns(scope);
  for (const regex of patterns.includes) await client.action('context', 'includeInContext', { contextName: name, regex }, signal);
  for (const regex of patterns.excludes) await client.action('context', 'excludeFromContext', { contextName: name, regex }, signal);
  await client.action('context', 'setContextInScope', { contextName: name, booleanInScope: 'true' }, signal);
  await client.action('core', 'setMode', { mode: 'protect' }, signal);
  return context.contextId;
}
