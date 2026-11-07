import express from 'express';
import { PipelineRunner } from './pipeline/pipeline-runner.js';
import { buildSecurityPipeline, type ScannerTask, type UrlAnalysisTask } from './pipelines/security-pipeline.js';
import { loadConfig, WebSecurityScanner } from './modules/web-security/index.js';
import { createZapBackend } from './modules/web-security/integrations/zap.js';
import { UrlAnalyzer } from './modules/url-analysis/index.js';

export function createApp(options: { scanner?: ScannerTask; urlAnalyzer?: UrlAnalysisTask } = {}) {
  const config = loadConfig();
  const scanner = options.scanner ?? new WebSecurityScanner(config, { zap: createZapBackend(config) });
  const urlAnalyzer = options.urlAnalyzer ?? new UrlAnalyzer();
  const dag = buildSecurityPipeline(scanner, urlAnalyzer);
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

  app.post('/api/url-analysis', async (req, res) => {
    const cancellation = new AbortController();
    const disconnected = () => { if (!res.writableEnded) cancellation.abort(); };
    res.once('close', disconnected);
    try {
      const result = await urlAnalyzer.analyze(req.body, cancellation.signal);
      res.status(result.status === 'blocked' ? 403 : result.url === null ? 400 : result.status === 'failed' ? 502 : 200).json(result);
    } finally { res.removeListener('close', disconnected); }
  });

  const errors: express.ErrorRequestHandler = (error: unknown, _req, res, _next) => {
    const status = error && typeof error === 'object' && 'status' in error ? Number(error.status) : 500;
    res.status(status === 400 || status === 413 ? status : 500).json({ error: status === 400 ? 'Invalid JSON request' : status === 413 ? 'Request body too large' : 'Analysis failed' });
  };
  app.use(errors);

  return app;
}
