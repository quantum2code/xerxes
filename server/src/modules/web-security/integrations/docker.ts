import { spawn } from 'node:child_process';

export type DockerRunner = (args: string[], options?: { signal?: AbortSignal; input?: string; timeoutMs?: number }) => Promise<string>;
/** No shell interpolation. Never include process output/arguments in report errors: these can contain secrets. */
export const runDocker: DockerRunner = (args, options = {}) => new Promise((resolve, reject) => {
  const child = spawn('docker', args, { shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const chunks: Buffer[] = [];
  let size = 0;
  let settled = false;
  const fail = () => { if (!settled) { settled = true; child.kill(); reject(new Error('Docker operation failed')); } };
  const timer = setTimeout(fail, options.timeoutMs ?? 10_000);
  const abort = () => fail();
  options.signal?.addEventListener('abort', abort, { once: true });
  if (options.signal?.aborted) fail();
  child.on('error', fail);
  child.stdin.on('error', fail);
  child.stdout.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 5_242_880) fail(); else chunks.push(chunk); });
  child.stderr.on('data', () => { /* Drain without logging raw errors. */ });
  child.on('close', (code) => {
    clearTimeout(timer); options.signal?.removeEventListener('abort', abort);
    if (!settled) { settled = true; if (code === 0) resolve(Buffer.concat(chunks).toString('utf8')); else reject(new Error('Docker operation failed')); }
  });
  child.stdin.end(options.input);
});
