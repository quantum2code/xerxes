import type { Engine2Error } from './types.js';
export class Engine2Failure extends Error {
  constructor(public readonly code: string, message: string) { super(message); }
}
export function scanError(stage: Engine2Error['stage'], error: unknown, signal?: AbortSignal): Engine2Error {
  if (signal?.aborted) return { stage, code: signal.reason?.name === 'TimeoutError' ? 'TIMEOUT' : 'CANCELLED', message: 'Operation interrupted; coverage is incomplete' };
  if (error instanceof Engine2Failure) return { stage, code: error.code, message: error.message };
  return { stage, code: 'OPERATION_FAILED', message: 'Scanner operation failed; raw error details withheld' };
}
export const elapsed = (start: number) => Math.round(performance.now() - start);
