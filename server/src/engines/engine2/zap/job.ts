import { Engine2Failure } from '../errors.js';
import { ApprovedScope } from '../scope/validator.js';
import type { ZapClient } from './client.js';
import type { Engine2Config } from '../types.js';

export interface GatewayStatistics { forwarded: number; denied: number; failures: number; exhausted: boolean; }
export interface ZapJob {
  id: string; scope: ApprovedScope; client: ZapClient; contextId: string; config: Engine2Config;
  enterPhase(phase: 'crawl' | 'active', signal: AbortSignal): Promise<void>;
  statistics(signal: AbortSignal): Promise<GatewayStatistics>;
  exclusive<T>(signal: AbortSignal, operation: () => Promise<T>): Promise<T>;
  recordEndpoints(urls: string[]): void;
  endpoints(): string[];
  close(): Promise<void>;
}
export type JobFactory = (scope: ApprovedScope, signal: AbortSignal) => Promise<ZapJob>;
export function assertJob(job: ZapJob, scope: ApprovedScope): void {
  ApprovedScope.assert(scope);
  if (job.scope !== scope || !/^\d+$/.test(job.contextId)) throw new Engine2Failure('JOB_SCOPE_MISMATCH', 'ZAP session does not belong to this approved scope');
}
