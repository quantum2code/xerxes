import type { ExecutionContext } from '../../pipeline/execution-context.js';
import { MlPhishingModule } from '../../modules/threat-detection/ml-phishing/index.js';
import type { MlPhishingAnalyzer } from '../../modules/threat-detection/ml-phishing/index.js';

import { getValidatedUrl } from './validate-url.js';

export function createMlPhishingHandler(model?: unknown) {
  return createMlPhishingModuleHandler(new MlPhishingModule(model));
}

export function createMlPhishingModuleHandler(module: MlPhishingAnalyzer) {
  if (module.name !== 'mlPhishingDetection') throw new TypeError('Expected an ML phishing module');
  return (context: ExecutionContext) => module.analyze(getValidatedUrl(context));
}
