import type { Evidence, DetectorModule } from '../contracts/evidence.js';
import type { ModuleStatus } from '../contracts/module-result.js';

export interface Finding {
  ruleId: string;
  severity: 'info' | 'medium' | 'high';
  message: string;
  evidence: Evidence[];
}

export interface AssessmentRule {
  id: string;
  /** One rule can produce findings for multiple hosts/targets. Rules are trusted application code. */
  evaluate(evidence: readonly Evidence[]): Finding[];
}

export interface ThreatAssessmentReport {
  policyVersion: string;
  riskLevel: 'unknown' | 'low' | 'medium' | 'high';
  summary: string;
  findings: Finding[];
  incompleteModules: { module: DetectorModule; status: ModuleStatus | 'missing'; issues: string[] }[];
}

export interface AssessmentOptions {
  /** Elevates matches from these caller-maintained sources to high severity. No implicit trust. */
  trustedBlacklistSources?: readonly string[];
}
