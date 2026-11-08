import { ThreatDetectionModule } from '../contracts/module.js';
import { DETECTOR_MODULES } from '../contracts/evidence.js';
import type { ModuleResult } from '../contracts/module-result.js';
import type { AssessmentRule, ThreatAssessmentReport } from './types.js';
import { createAssessmentRules } from './rules.js';

/** Collect evidence, run explicit rules, and disclose incomplete checks. No scoring framework. */
export class ThreatAssessment extends ThreatDetectionModule<readonly ModuleResult[], ThreatAssessmentReport> {
  readonly name = 'threatAssessment';
  private readonly rules: readonly AssessmentRule[];

  constructor(rules: readonly AssessmentRule[] = createAssessmentRules(), private readonly policyVersion = 'simple-v1') {
    super();
    if (rules.some((rule) => !rule.id.trim()) || new Set(rules.map(({ id }) => id)).size !== rules.length) {
      throw new TypeError('Assessment rules require unique nonempty IDs');
    }
    this.rules = rules.map((rule) => ({ id: rule.id, evaluate: rule.evaluate }));
  }

  analyze(results: readonly ModuleResult[]): ThreatAssessmentReport {
    return this.assess(results);
  }

  assess(results: readonly ModuleResult[]): ThreatAssessmentReport {
    if (new Set(results.map(({ module }) => module)).size !== results.length) {
      throw new TypeError('Assessment requires at most one result per detector');
    }
    for (const result of results) {
      if (!DETECTOR_MODULES.includes(result.module)
        || !['completed', 'partial', 'not_configured', 'error'].includes(result.status)) {
        throw new TypeError('Invalid detector result supplied to assessment');
      }
      if (result.evidence.some((item) => item.module !== result.module)) {
        throw new TypeError('Evidence must identify its originating detector');
      }
    }
    const evidence = structuredClone(results.flatMap((result) => result.evidence));
    const incompleteModules: ThreatAssessmentReport['incompleteModules'] = DETECTOR_MODULES.flatMap((module) => {
      const result = results.find((item) => item.module === module);
      return result?.status === 'completed' ? []
        : [{ module, status: result?.status ?? 'missing', issues: [...result?.issues ?? ['Detector result was not supplied']] }];
    });
    const findings = this.rules.flatMap((rule) => {
      const matches = rule.evaluate(evidence);
      if (matches.some((finding) => finding.ruleId !== rule.id)) throw new TypeError('Finding ruleId must match the evaluated rule');
      return matches;
    });
    let riskLevel: ThreatAssessmentReport['riskLevel'];
    if (findings.some(({ severity }) => severity === 'high')) {
      riskLevel = 'high';
    } else if (findings.some(({ severity }) => severity === 'medium')) {
      riskLevel = 'medium';
    } else if (incompleteModules.length > 0) {
      riskLevel = 'unknown';
    } else {
      riskLevel = 'low';
    }

    let summary: string;
    if (riskLevel === 'unknown') {
      summary = 'No elevated-risk finding from completed checks; assessment coverage is incomplete.';
    } else if (riskLevel === 'low') {
      summary = 'No elevated-risk finding under the configured rules; this is not a safety guarantee.';
    } else {
      const severity = riskLevel === 'high' ? 'High' : 'Medium';
      const coverage = incompleteModules.length > 0 ? '; assessment coverage is incomplete' : '';
      summary = `${severity}-severity findings require review${coverage}.`;
    }
    return { policyVersion: this.policyVersion, riskLevel, summary, findings: structuredClone(findings), incompleteModules };
  }
}
