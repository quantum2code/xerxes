import type { ExecutionContext } from '../../pipeline/execution-context.js';
import { BasicUrlAnalysisModule } from '../../modules/threat-detection/basic-url-analysis/index.js';

import { getValidatedUrl } from './validate-url.js';

const module = new BasicUrlAnalysisModule();

export function handleBasicUrlAnalysis(context: ExecutionContext) {
  return module.analyze(getValidatedUrl(context, 'original'));
}
