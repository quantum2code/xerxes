import express from 'express';
import type { ErrorRequestHandler } from 'express';
import { PipelineRunner } from './pipeline/pipeline-runner.js';
import { buildThreatDetectionPipeline } from './pipelines/threat-detection-pipeline.js';
import type { ThreatDetectionPipelineOptions } from './pipelines/threat-detection-pipeline.js';
import { InvalidThreatDetectionInputError } from './tasks/threat-detection/validate-url.js';

const BODY_LIMIT = '16kb';

/** Configuration is server-owned, never read from request bodies. Reuses one runner across requests. */
export function createApp(options: ThreatDetectionPipelineOptions = {}) {
  const dag = buildThreatDetectionPipeline(options);
  const runner = new PipelineRunner(dag);
  const app = express();
  app.use(express.json({ limit: BODY_LIMIT }));

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  app.post('/api/analyze', async (req, res) => {
    if (!req.is('application/json')) {
      res.status(415).json({ error: { code: 'unsupported_media_type', message: 'Use Content-Type: application/json' } });
      return;
    }
    // validateUrl is the graph's first task; no second HTTP-specific validation pass.
    const results = await runner.run(req.body);
    res.json(results);
  });

  const handleError: ErrorRequestHandler = (error: unknown, _req, res, next) => {
    if (res.headersSent) { next(error); return; }
    const type = error && typeof error === 'object' && 'type' in error ? error.type : undefined;
    if (error instanceof InvalidThreatDetectionInputError) {
      res.status(400).json({ error: {
        code: 'invalid_input', message: 'Provide an object with a valid explicit HTTP(S) url without credentials',
      } });
    } else if (type === 'entity.parse.failed') {
      res.status(400).json({ error: { code: 'invalid_json', message: 'Request body must be valid JSON' } });
    } else if (type === 'entity.too.large') {
      res.status(413).json({ error: { code: 'body_too_large', message: 'Request body exceeds 16 KB' } });
    } else if (type === 'charset.unsupported' || type === 'encoding.unsupported') {
      res.status(415).json({ error: { code: 'unsupported_media_type', message: 'Unsupported body encoding' } });
    } else {
      // Do not expose raw URLs, secrets, provider messages, native errors, or stack traces.
      res.status(500).json({ error: { code: 'analysis_failed', message: 'Threat analysis failed' } });
    }
  };
  app.use(handleError);

  return app;
}
