import { PolicyError } from '../../shared/network/policy.js';
import type { AnalysisError } from './types.js';

export class AnalysisFailure extends Error {
  constructor(public readonly code: string, message: string) { super(message); }
}
export function structuredError(stage: AnalysisError['stage'], error: unknown, signal?: AbortSignal): AnalysisError {
  if (error instanceof PolicyError) return { stage, code: 'NETWORK_BLOCKED', message: 'Destination prohibited by network policy', retryable: false };
  if (error instanceof AnalysisFailure) return { stage, code: error.code, message: error.message, retryable: false };
  if (signal?.aborted) {
    const timeout = signal.reason instanceof Error && signal.reason.name === 'TimeoutError';
    return { stage, code: timeout ? 'TIMEOUT' : 'CANCELLED', message: timeout ? 'Operation deadline exceeded' : 'Operation cancelled', retryable: timeout };
  }
  let current = error;
  let code = '';
  for (let i = 0; i < 4 && current && typeof current === 'object'; i++) {
    if ('code' in current && typeof current.code === 'string') code = current.code;
    current = 'cause' in current ? current.cause : null;
  }
  const allowed = new Set(['ENOTFOUND', 'ENODATA', 'ETIMEOUT', 'ETIMEDOUT', 'EAI_AGAIN', 'ESERVFAIL', 'EREFUSED', 'ECANCELLED', 'ECONNREFUSED', 'ECONNRESET', 'ENETUNREACH', 'EHOSTUNREACH',
    'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT', 'UND_ERR_HEADERS_OVERFLOW', 'UND_ERR_RES_EXCEEDED_MAX_SIZE', 'UND_ERR_SOCKET', 'HPE_INVALID_CONSTANT', 'HPE_INVALID_HEADER_TOKEN']);
  if (!allowed.has(code)) code = 'OPERATION_FAILED';
  return { stage, code, message: code.startsWith('ERR_TLS') || /CERT|SELF_SIGNED|LEAF_SIGNATURE/.test(code) ? 'TLS connection verification failed' : 'Network operation did not complete',
    retryable: ['ETIMEOUT', 'ETIMEDOUT', 'EAI_AGAIN', 'ESERVFAIL', 'ECONNRESET', 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT', 'UND_ERR_SOCKET'].includes(code) };
}
export async function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted();
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener('abort', abort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}
