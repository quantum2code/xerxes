import type { ExecutionContext } from '../../pipeline/execution-context.js';
import { BlacklistModule } from '../../modules/threat-detection/blacklist/index.js';
import type { BlacklistOptions } from '../../modules/threat-detection/blacklist/index.js';
import { getValidatedUrl } from './validate-url.js';

export function createBlacklistHandler(options: BlacklistOptions = {}) {
  const module = new BlacklistModule(options);
  return (context: ExecutionContext) => module.analyze(getValidatedUrl(context));
}
