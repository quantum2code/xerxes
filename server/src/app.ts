import express from 'express';
import { PipelineRunner } from './pipeline/pipeline-runner.js';
import { buildSecurityPipeline, type ScannerTask } from './pipelines/security-pipeline.js';
import { loadConfig, WebSecurityScanner } from './modules/web-security/index.js';
import { createZapBackend } from './modules/web-security/integrations/zap.js'; import type { CertificateTask } from './modules/certificate-validation/index.js';

export function createApp(options: { scanner?: ScannerTask; certificate?: CertificateTask } = {}) {
  const config = loadConfig();
  const scanner = options.scanner ?? new WebSecurityScanner(config, { zap: createZapBackend(config) });
  const dag = buildSecurityPipeline(scanner, options.certificate);
  const runner = new PipelineRunner(dag);
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb' }));

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  app.post('/api/analyze', async (req, res) => {
    const results = await runner.run(req.body);
    res.json(results);
  });

  app.post('/api/web-security/scan', async (req, res) => {
    const result = await scanner.scan(req.body);
    res.status(result.status === 'blocked' ? 403 : result.status === 'failed' ? 502 : 200).json(result);
  });

  const errors: express.ErrorRequestHandler = (error: unknown, _req, res, _next) => {
    const status = error && typeof error === 'object' && 'status' in error ? Number(error.status) : 500;
    res.status(status === 400 || status === 413 ? status : 500).json({ error: status === 400 ? 'Invalid JSON request' : status === 413 ? 'Request body too large' : 'Analysis failed' });
  };
  app.use(errors);

  return app;
}
