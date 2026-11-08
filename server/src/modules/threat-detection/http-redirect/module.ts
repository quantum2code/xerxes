import { ThreatDetectionModule } from '../contracts/module.js';
import type { Evidence } from '../contracts/evidence.js';
import type { ModuleResult } from '../contracts/module-result.js';
import { normalizedHostname, parseHttpUrl } from '../shared/url.js';
import { detectHttpRedirects } from './analyzer.js';
import type { HttpRedirectOptions, HttpRedirectResult } from './types.js';

export class HttpRedirectModule extends ThreatDetectionModule<string, ModuleResult<HttpRedirectResult>> {
  readonly name = 'httpRedirectDetection';
  private readonly options: HttpRedirectOptions;

  constructor(options: HttpRedirectOptions = {}) {
    super();
    this.options = { ...options };
  }

  async analyze(input: string): Promise<ModuleResult<HttpRedirectResult>> {
    parseHttpUrl(input);
    const details = await detectHttpRedirects(input, this.options);
    const evidence: Evidence[] = [];
    for (const hop of details.chain) {
      if (!hop.redirect) continue;
      const target = new URL(hop.redirect.url);
      const from = new URL(hop.url);
      evidence.push({ module: this.name, hostname: normalizedHostname(target), target: 'redirect', code: 'REDIRECT_HOP',
        fromHostname: normalizedHostname(from), fromScheme: from.protocol as 'http:' | 'https:',
        toScheme: target.protocol as 'http:' | 'https:', crossDomain: hop.redirect.crossDomain,
        followed: hop.redirect.followed,
      });
    }
    let status: ModuleResult['status'];
    if (details.status === 'complete') {
      status = 'completed';
    } else if (details.chain.length > 0) {
      status = 'partial';
    } else {
      status = 'error';
    }
    return { module: this.name, status,
      evidence, details, issues: details.status === 'complete' ? [] : [`Redirect inspection incomplete: ${details.error?.code ?? details.status}`] };
  }
}
