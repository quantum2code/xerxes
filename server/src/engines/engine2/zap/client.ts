import { z } from 'zod';
import { Engine2Failure } from '../errors.js';

export interface ApiRequest { component: string; kind: 'view' | 'action'; name: string; params: Record<string, string>; }
export type ZapTransport = (request: ApiRequest, signal: AbortSignal) => Promise<unknown>;
export const idSchema = z.string().regex(/^\d+$/);
export const countSchema = z.union([z.number().int().nonnegative(), z.string().regex(/^\d+$/).transform(Number)]).refine(Number.isSafeInteger);
export const progressSchema = z.object({ status: countSchema.refine((n) => n <= 100) });
export const okSchema = z.object({ Result: z.literal('OK') });
/** Per-job state, no global client defaults; transport never automatically retries scan-start calls. */
export class ZapClient {
  constructor(private readonly transport: ZapTransport, private readonly timeoutMs: number) {}
  async call<T>(component: string, kind: 'view' | 'action', name: string, params: Record<string, string>, schema: z.ZodType<T>, parent: AbortSignal): Promise<T> {
    const signal = AbortSignal.any([parent, AbortSignal.timeout(this.timeoutMs)]);
    signal.throwIfAborted();
    const raw = await this.transport({ component, kind, name, params }, signal);
    signal.throwIfAborted();
    if (raw && typeof raw === 'object' && ('code' in raw || 'error' in raw)) throw new Engine2Failure('ZAP_API_ERROR', 'ZAP rejected the operation; management details withheld');
    const parsed = schema.safeParse(raw);
    if (!parsed.success) throw new Engine2Failure('INVALID_ZAP_RESPONSE', 'Unexpected ZAP API response shape');
    return parsed.data;
  }
  action(component: string, name: string, params: Record<string, string>, signal: AbortSignal): Promise<unknown> {
    return this.call(component, 'action', name, params, okSchema, signal);
  }
}
