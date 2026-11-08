import { ThreatDetectionModule } from '../contracts/module.js';
import type { Evidence } from '../contracts/evidence.js';
import type { ModuleResult } from '../contracts/module-result.js';
import { normalizedHostname, parseHttpUrl } from '../shared/url.js';
import { createMlPhishingDetector } from './analyzer.js';
import type { MlPhishingResult } from './types.js';

/** Shared envelope for synchronous logistic and asynchronous pretrained inference. */
export function toMlPhishingModuleResult(input: string, details: MlPhishingResult): ModuleResult<MlPhishingResult> {
  const module = 'mlPhishingDetection';
  const evidence: Evidence[] = details.status === 'predicted' ? [{
    module, hostname: normalizedHostname(parseHttpUrl(input)), target: 'submitted',
    code: 'ML_PREDICTION', probability: details.phishingProbability, threshold: details.threshold,
    modelId: details.modelId, trainedAt: details.trainedAt,
  }] : [];
  return { module, status: details.status === 'predicted' ? 'completed' : 'not_configured',
    evidence, details, issues: details.status === 'predicted' ? [] : ['No trained ML model configured'] };
}

export class MlPhishingModule extends ThreatDetectionModule<string, ModuleResult<MlPhishingResult>> {
  readonly name = 'mlPhishingDetection';
  private readonly detect: (input: string) => MlPhishingResult;

  constructor(model?: unknown) {
    super();
    this.detect = createMlPhishingDetector(model);
  }

  analyze(input: string): ModuleResult<MlPhishingResult> {
    return toMlPhishingModuleResult(input, this.detect(input));
  }
}
