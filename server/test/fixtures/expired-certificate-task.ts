import type { CertificateTask } from '../../src/modules/certificate-validation/index.js';

/** Offline stand-in for the real certificate task so pipeline tests never touch the network. */
export const expiredCertificateTask: CertificateTask = async () => ({
  status: 'ok',
  valid: false,
  findings: [{ id: 'cert.expired', severity: 'high', message: 'Certificate expired 1 day(s) ago' }],
});