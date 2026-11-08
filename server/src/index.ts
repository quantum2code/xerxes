import { createApp } from './app.js';
import { loadPretrainedMlPhishingModule } from './modules/threat-detection/ml-phishing/index.js';
import { createServerPipelineOptions } from './server-options.js';

async function main(): Promise<void> {
  // Explicit application configuration: library/pipeline defaults remain unconfigured.
  // Load once before listening. Never download a model or silently omit ML at startup.
  const mlModule = await loadPretrainedMlPhishingModule({ modelPath: process.env.PHISHING_ONNX_MODEL_PATH });
  try {
    const options = createServerPipelineOptions(mlModule);
    const app = createApp(options);
    if (!options.blacklist?.providers?.length) {
      console.warn('GOOGLE_SAFE_BROWSING_API_KEY is not set; blacklist checks are not configured.');
    }
    const port = Number(process.env.PORT ?? 3000);
    const server = app.listen(port, () => {
      const address = server.address();
      console.log(`Server listening on port ${address && typeof address === 'object' ? address.port : port}`);
    });
    let stopping: Promise<void> | undefined;
    const stop = (): Promise<void> => stopping ??= (async () => {
      // Stop accepting requests and drain active HTTP/pipeline work before disposing ML.
      await new Promise<void>((resolve) => { server.close(() => resolve()); });
      await mlModule.dispose();
    })();
    const shutdown = () => {
      void stop().catch(() => {
        console.error('Server shutdown failed');
        process.exitCode = 1;
      });
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
    server.once('error', () => {
      console.error('Server failed to listen');
      process.exitCode = 1;
      shutdown();
    });
  } catch (error) {
    await mlModule.dispose();
    throw error;
  }
}

void main().catch(() => {
  console.error('Server startup failed. Provision the verified model with pnpm ml:download, and check server configuration.');
  process.exitCode = 1;
});
