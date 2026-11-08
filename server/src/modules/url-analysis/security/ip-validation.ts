import { PolicyError, publicAddress } from '../../../shared/network/policy.js';
import { parseUrl } from '../url/parser.js';
import type { UrlAnalysisConfig } from '../types.js';

export { classifyAddress, publicAddress, resolvePublic } from '../../../shared/network/policy.js';
export function assertNetworkTarget(url: URL, config: UrlAnalysisConfig): void {
  const parsed = parseUrl({ url: url.href }, config.maxUrlLength);
  if (!config.allowedPorts.includes(parsed.data.port)) throw new PolicyError('Destination port prohibited');
  if (/(?:^|\.)(?:localhost|local|internal|home|lan|test|invalid|onion)$/i.test(parsed.data.hostname) ||
      (parsed.data.isIpAddress && !publicAddress(parsed.data.hostname))) throw new PolicyError('Destination hostname/address prohibited');
}
