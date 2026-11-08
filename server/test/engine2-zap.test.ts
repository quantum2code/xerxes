import assert from 'node:assert/strict';
import test from 'node:test';
import { z } from 'zod';
import { ZapClient } from '../src/engines/engine2/zap/client.js';
import { createContext } from '../src/engines/engine2/zap/context.js';
import { approved } from './helpers/engine2.js';

test('typed adapter rejects API errors/malformed responses without leaking management details', async () => {
  for (const raw of [{ code: 'bad', message: 'secret-key' }, { version: 42 }]) {
    const client = new ZapClient(async () => raw, 100);
    await assert.rejects(client.call('core', 'view', 'version', {}, z.object({ version: z.string() }), new AbortController().signal), (error: unknown) => error instanceof Error && !error.message.includes('secret-key'));
  }
});
test('context setup uses named bounded inclusion/exclusion rules and protect mode', async () => {
  const calls: string[] = [];
  const client = new ZapClient(async (req) => { calls.push(req.name); return req.name === 'newContext' ? { contextId: '7' } : { Result: 'OK' }; }, 100);
  const scope = await approved();
  assert.equal(await createContext(client, scope, new AbortController().signal), '7');
  assert.deepEqual(calls, ['newContext', 'includeInContext', 'excludeFromContext', 'setContextInScope', 'setMode']);
});
test('client instances never share transport configuration or retry mutation requests', async () => {
  let a = 0; let b = 0;
  const first = new ZapClient(async () => { a++; throw new Error(); }, 100);
  const second = new ZapClient(async () => { b++; return { Result: 'OK' }; }, 100);
  await assert.rejects(first.action('spider', 'scan', {}, new AbortController().signal));
  await second.action('core', 'setMode', {}, new AbortController().signal);
  assert.equal(a, 1); assert.equal(b, 1);
});
