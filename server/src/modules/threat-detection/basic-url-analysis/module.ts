import { ThreatDetectionModule } from '../contracts/module.js';
import type { Evidence } from '../contracts/evidence.js';
import type { ModuleResult } from '../contracts/module-result.js';
import { analyzeBasicUrl } from './analyzer.js';
import type { BasicUrlAnalysis } from './types.js';

export class BasicUrlAnalysisModule extends ThreatDetectionModule<string, ModuleResult<BasicUrlAnalysis>> {
  readonly name = 'basicUrlAnalysis';

  analyze(input: string): ModuleResult<BasicUrlAnalysis> {
    const details = analyzeBasicUrl(input);
    const evidence: Evidence[] = details.signals.map((signal) => {
      const source = { module: this.name, hostname: details.hostname, target: 'submitted' } as const;
      if (signal.code === 'sensitive_keywords') {
        return { ...source, code: 'AUTH_KEYWORD', location: signal.location, keywords: [...signal.evidence.matches ?? []] };
      }
      return { ...source, code: 'URL_STRUCTURE', signal: signal.code, location: signal.location,
        value: signal.evidence.value, ...(signal.evidence.threshold === undefined ? {} : { threshold: signal.evidence.threshold }) };
    });
    return { module: this.name, status: 'completed', evidence, details, issues: [] };
  }
}
