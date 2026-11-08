import type { ExecutionContext } from '../../pipeline/execution-context.js';
import { ThreatAssessment, createAssessmentRules } from '../../modules/threat-detection/assessment/index.js';
import type { AssessmentOptions } from '../../modules/threat-detection/assessment/index.js';
import { DETECTOR_MODULES } from '../../modules/threat-detection/contracts/evidence.js';
import type { ModuleResult } from '../../modules/threat-detection/contracts/module-result.js';

export function createAssessmentHandler(options: AssessmentOptions = {}) {
  const assessment = new ThreatAssessment(createAssessmentRules(options));
  return (context: ExecutionContext) => {
    const results = DETECTOR_MODULES.map((name) => {
      const result = context.results[name];
      if (!result || typeof result !== 'object' || !('module' in result) || result.module !== name) {
        throw new Error(`Missing or invalid detector dependency: ${name}`);
      }
      return result as ModuleResult;
    });
    return assessment.assess(results);
  };
}
