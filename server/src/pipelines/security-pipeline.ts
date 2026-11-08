import { DAG } from '../pipeline/dag.js';
import { Task } from '../pipeline/task.js';
import { buildSecurityPipeline as buildMockPipeline } from './mock-pipeline.js';
import { validateCertificate, type CertificateTask, type CertificateValidationResult } from '../modules/certificate-validation/index.js';
import type { ScanResult } from '../modules/web-security/types.js';

export interface ScannerTask { scan(input: unknown): Promise<ScanResult>; }

// The legacy assessment emits this text whenever certificateValidation.valid === false.
// Real findings replace it below so a real result is never labelled "Mock".
const MOCK_CERTIFICATE_FINDING = 'Mock certificate validation failed';

/** Preserve the legacy mocks and risk ownership; real tasks replace or extend the mocks. */
export function buildSecurityPipeline(scanner: ScannerTask, certificate: CertificateTask = validateCertificate): DAG {
  const legacy = buildMockPipeline();
  const assessment = legacy.getTask('securityAssessment');
  return new DAG([
    ...legacy.tasks.filter((task) => task.name !== 'securityAssessment' && task.name !== 'certificateValidation'),
    new Task({ name: 'certificateValidation', run: (context) => certificate(context.input) }),
    new Task({ name: 'webSecurityScan', run: (context) => scanner.scan(context.input) }),
    new Task({
      name: 'securityAssessment',
      dependencies: [...assessment.dependencies, 'webSecurityScan'],
      run: async (context) => {
        const previous = await assessment.run(context) as { findings: string[] };
        const scan = context.results.webSecurityScan as ScanResult;
        const cert = context.results.certificateValidation as CertificateValidationResult;
        return {
          findings: [
            ...previous.findings.filter((finding) => finding !== MOCK_CERTIFICATE_FINDING),
            ...cert.findings.map((finding) => `${finding.id}: ${finding.message}`),
          ],
          certificate: { status: cert.status, valid: cert.valid, reason: cert.reason, trustError: cert.trustError, coverageLimitations: cert.coverageLimitations },
          webSecurity: { status: scan.status, counts: scan.counts, findings: scan.findings, coverageLimitations: scan.coverageLimitations },
        };
      },
    }),
  ]);
}