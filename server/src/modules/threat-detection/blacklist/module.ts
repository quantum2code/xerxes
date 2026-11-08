import { ThreatDetectionModule } from '../contracts/module.js';
import type { Evidence } from '../contracts/evidence.js';
import type { ModuleResult } from '../contracts/module-result.js';
import { normalizedHostname, parseHttpUrl } from '../shared/url.js';
import { createBlacklistChecker } from './analyzer.js';
import type { BlacklistChecker, BlacklistOptions, BlacklistResult } from './types.js';

export class BlacklistModule extends ThreatDetectionModule<string, ModuleResult<BlacklistResult>> {
  readonly name = 'blacklistCheck';
  private readonly check: BlacklistChecker;
  private readonly configured: boolean;

  constructor(options: BlacklistOptions = {}) {
    super();
    this.check = createBlacklistChecker(options);
    this.configured = Boolean(options.providers?.length
      || options.snapshots?.some((snapshot) => snapshot.urls?.length || snapshot.domains?.length));
  }

  async analyze(input: string): Promise<ModuleResult<BlacklistResult>> {
    const details = await this.check(input);
    const hostname = normalizedHostname(parseHttpUrl(input));
    const evidence: Evidence[] = details.matches.map((match) => ({
      module: this.name, hostname, target: 'submitted', code: 'BLACKLIST_MATCH', source: match.source, sourceKind: match.kind,
    }));
    const successfulSources = details.checkedSources.length - details.errors.length;
    let status: ModuleResult['status'];
    if (!this.configured) {
      status = 'not_configured';
    } else if (details.errors.length === 0) {
      status = 'completed';
    } else if (successfulSources > 0 || evidence.length > 0) {
      status = 'partial';
    } else {
      status = 'error';
    }
    return { module: this.name, status, evidence, details,
      issues: !this.configured ? ['No nonempty blacklist source configured']
        : details.errors.map((error) => `${error.source}: ${error.code}`) };
  }
}
