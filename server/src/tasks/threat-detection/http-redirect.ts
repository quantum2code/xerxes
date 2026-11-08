import type { ExecutionContext } from '../../pipeline/execution-context.js';
import { HttpRedirectModule } from '../../modules/threat-detection/http-redirect/index.js';
import type { HttpRedirectOptions } from '../../modules/threat-detection/http-redirect/index.js';
import { getValidatedUrl } from './validate-url.js';

export function createHttpRedirectHandler(options: HttpRedirectOptions = {}) {
  const module = new HttpRedirectModule(options);
  return (context: ExecutionContext) => module.analyze(getValidatedUrl(context));
}
