import { ThreatDetectionModule } from '../contracts/module.js';
import type { Evidence } from '../contracts/evidence.js';
import type { ModuleResult } from '../contracts/module-result.js';
import { normalizedHostname, parseHttpUrl } from '../shared/url.js';
import { createBrandImpersonationDetector } from './analyzer.js';
import type { BrandDefinition, BrandImpersonationResult } from './types.js';

export class BrandImpersonationModule extends ThreatDetectionModule<string, ModuleResult<BrandImpersonationResult>> {
  readonly name = 'brandImpersonation';
  private readonly detect: (input: string) => BrandImpersonationResult;

  constructor(brands: readonly BrandDefinition[] = [], options: { maxEditDistance?: number } = {}) {
    super();
    this.detect = createBrandImpersonationDetector(brands, options);
  }

  analyze(input: string): ModuleResult<BrandImpersonationResult> {
    const details = this.detect(input);
    const hostname = normalizedHostname(parseHttpUrl(input));
    const evidence: Evidence[] = details.findings.map((finding) => ({
      module: this.name, hostname, target: 'submitted', code: 'BRAND_LOOKALIKE',
      brand: finding.brand, reason: finding.reason, officialDomains: [...finding.officialDomains],
      ...(finding.editDistance === undefined ? {} : { editDistance: finding.editDistance }),
    }));
    return { module: this.name, status: details.brandsChecked ? 'completed' : 'not_configured',
      evidence, details, issues: details.brandsChecked ? [] : ['No brand catalog configured'] };
  }
}
