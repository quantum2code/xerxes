import { z } from 'zod';
import { setTimeout as delay } from 'node:timers/promises';
import type { ZapClient } from './client.js';

export async function waitForZap(client: ZapClient, timeoutMs: number, parent: AbortSignal): Promise<string> {
  const signal = AbortSignal.any([parent, AbortSignal.timeout(timeoutMs)]);
  while (true) {
    signal.throwIfAborted();
    try { return (await client.call('core', 'view', 'version', {}, z.object({ version: z.string().min(1) }), signal)).version; }
    catch { await delay(250, undefined, { signal }); }
  }
}
