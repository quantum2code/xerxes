import { DAG } from '../pipeline/dag.js';
import { Task } from '../pipeline/task.js';
import { DETECTOR_MODULES } from '../modules/threat-detection/contracts/evidence.js';
import type { DetectorModule } from '../modules/threat-detection/contracts/evidence.js';
import type { TaskDefinition } from '../pipeline/task.js';
import type { AssessmentOptions } from '../modules/threat-detection/assessment/index.js';
import type { BlacklistOptions } from '../modules/threat-detection/blacklist/index.js';
import type { HttpRedirectOptions } from '../modules/threat-detection/http-redirect/index.js';
import type { MlPhishingAnalyzer } from '../modules/threat-detection/ml-phishing/index.js';
import {
  createAssessmentHandler,
  createBlacklistHandler,
  createBrandImpersonationHandler,
  createHttpRedirectHandler,
  createMlPhishingHandler,
  createMlPhishingModuleHandler,
  handleBasicUrlAnalysis,
  handleValidateUrl,
} from '../tasks/threat-detection/index.js';
import type { BrandImpersonationHandlerOptions } from '../tasks/threat-detection/index.js';

export interface ThreatDetectionPipelineOptions {
  redirects?: HttpRedirectOptions;
  mlModel?: unknown;
  /** Explicitly preloaded async ML module; mutually exclusive with mlModel. Caller owns disposal. */
  mlModule?: MlPhishingAnalyzer;
  blacklist?: BlacklistOptions;
  brandImpersonation?: BrandImpersonationHandlerOptions;
  assessment?: AssessmentOptions;
}

/**
 * Builds Engine 1 without executing it. After URL validation, all five detectors run independently
 * against the submitted URL, not redirect destinations. Running the DAG enables redirect network I/O
 * unless a trusted transport is injected. Missing ML/blacklist/brand configuration stays explicit
 * in module evidence envelopes. The final assessment evaluates rules after all five results exist.
 * Expected network/provider failures produce incomplete results rather than blocking assessment.
 */
export function buildThreatDetectionPipeline(options: ThreatDetectionPipelineOptions = {}): DAG {
  if (options.mlModule !== undefined && options.mlModel !== undefined) {
    throw new TypeError('Configure either mlModel or mlModule, not both');
  }
  const mlHandler = options.mlModule === undefined ? createMlPhishingHandler(options.mlModel)
    : createMlPhishingModuleHandler(options.mlModule);
  const handlers: Record<DetectorModule, TaskDefinition['run']> = {
    httpRedirectDetection: createHttpRedirectHandler(options.redirects),
    basicUrlAnalysis: handleBasicUrlAnalysis,
    mlPhishingDetection: mlHandler,
    blacklistCheck: createBlacklistHandler(options.blacklist),
    brandImpersonation: createBrandImpersonationHandler(options.brandImpersonation),
  };
  return new DAG([
    new Task({ name: 'validateUrl', run: handleValidateUrl }),
    ...DETECTOR_MODULES.map((name) => new Task({ name, dependencies: ['validateUrl'], run: handlers[name] })),
    new Task({
      name: 'threatAssessment',
      dependencies: DETECTOR_MODULES,
      run: createAssessmentHandler(options.assessment),
    }),
  ]);
}
