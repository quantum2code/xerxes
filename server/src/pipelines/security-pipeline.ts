import { DAG } from '../pipeline/dag.js';
import { Task } from '../pipeline/task.js';
import { buildSecurityPipeline as buildMockPipeline } from './mock-pipeline.js';
import type { ScanResult } from '../modules/web-security/types.js';
import type { UrlAnalysisResult } from '../modules/url-analysis/types.js';
import type { Engine2ScanResult } from '../engines/engine2/types.js';

export interface ScannerTask { scan(input: unknown): Promise<ScanResult>; }
export interface UrlAnalysisTask { analyze(input: unknown, cancellation?: AbortSignal): Promise<UrlAnalysisResult>; }
export interface Engine2Task { scan(input: unknown): Promise<Engine2ScanResult>; }

/** Preserve the legacy mocks and risk ownership; only add scanner output to aggregation. */
export function buildSecurityPipeline(scanner: ScannerTask, analyzer?: UrlAnalysisTask, engine2?: Engine2Task): DAG {
  const legacy = buildMockPipeline();
  const assessment = legacy.getTask('securityAssessment');
  return new DAG([
    ...legacy.tasks.filter((task) => task.name !== 'securityAssessment'),
    ...(analyzer ? [new Task({ name: 'urlAnalysis', run: (context) => analyzer.analyze(context.input) })] : []),
    new Task({ name: 'webSecurityScan', run: (context) => scanner.scan(context.input) }),
    ...(engine2 ? [new Task({ name: 'engine2', retry: { maxRetries: 0 }, run: (context) => {
      const input = context.input;
      return engine2.scan(input && typeof input === 'object' && 'engine2' in input ? input.engine2 : undefined);
    } })] : []),
    new Task({
      name: 'securityAssessment',
      dependencies: [...assessment.dependencies, 'webSecurityScan', ...(analyzer ? ['urlAnalysis'] : []), ...(engine2 ? ['engine2'] : [])],
      run: async (context) => {
        const previous = await assessment.run(context) as { findings: string[] };
        const scan = context.results.webSecurityScan as ScanResult;
        const url = context.results.urlAnalysis as UrlAnalysisResult | undefined;
        const zap = context.results.engine2 as Engine2ScanResult | undefined;
        return { ...previous, webSecurity: { status: scan.status, counts: scan.counts, findings: scan.findings, coverageLimitations: scan.coverageLimitations },
          ...(url ? { urlAnalysis: { status: url.status, dnsStatus: url.dns.status, httpStatus: url.http.status, errors: url.errors } } : {}),
          ...(zap ? { engine2: { status: zap.status, counts: zap.counts, findings: zap.findings, errors: zap.errors, limitations: zap.limitations } } : {}) };
      },
    }),
  ]);
}
