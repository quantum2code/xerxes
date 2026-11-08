import type { DetectorModule, Evidence } from './evidence.js';

export type ModuleStatus = 'completed' | 'partial' | 'not_configured' | 'error';

/** Evidence is factual; assessment rules, not detector modules, assign threat severity. */
export interface ModuleResult<TDetails = unknown> {
  module: DetectorModule;
  status: ModuleStatus;
  evidence: Evidence[];
  /** Raw detector diagnostics may contain sensitive URL data; do not expose indiscriminately. */
  details: TDetails;
  issues: string[];
}
