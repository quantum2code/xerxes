import type { ExecutionContext } from '../../pipeline/execution-context.js';
import { BrandImpersonationModule } from '../../modules/threat-detection/brand-impersonation/index.js';
import type { BrandDefinition } from '../../modules/threat-detection/brand-impersonation/index.js';
import { getValidatedUrl } from './validate-url.js';

export interface BrandImpersonationHandlerOptions {
  brands?: readonly BrandDefinition[];
  maxEditDistance?: number;
}

export function createBrandImpersonationHandler(options: BrandImpersonationHandlerOptions = {}) {
  const module = new BrandImpersonationModule(options.brands, { maxEditDistance: options.maxEditDistance });
  return (context: ExecutionContext) => module.analyze(getValidatedUrl(context));
}
