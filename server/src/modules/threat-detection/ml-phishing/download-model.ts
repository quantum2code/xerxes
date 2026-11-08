/** Explicit setup command only. Never imported by detector or pipeline code. */
import { createHash, randomUUID } from 'node:crypto';
import { link, mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_PRETRAINED_MODEL_PATH, PRETRAINED_URL_MODEL } from './pretrained-model.js';

const destination = fileURLToPath(DEFAULT_PRETRAINED_MODEL_PATH);
const digest = (data: Uint8Array) => createHash('sha256').update(data).digest('hex');

async function download(): Promise<void> {
  try {
    const existing = await readFile(destination);
    if (existing.length !== PRETRAINED_URL_MODEL.bytes || digest(existing) !== PRETRAINED_URL_MODEL.sha256) {
      throw new Error('Existing model fails integrity verification; remove it explicitly before downloading again');
    }
    console.log(`Verified existing model: ${destination}`);
    return;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }

  const response = await fetch(PRETRAINED_URL_MODEL.url, { signal: AbortSignal.timeout(120_000) });
  if (!response.ok || !response.body) throw new Error(`Model download failed (HTTP ${response.status})`);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.length;
      if (bytes > PRETRAINED_URL_MODEL.bytes) throw new Error('Model download exceeds expected size');
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
  const data = Buffer.concat(chunks);
  if (bytes !== PRETRAINED_URL_MODEL.bytes || digest(data) !== PRETRAINED_URL_MODEL.sha256) {
    throw new Error('Downloaded model fails size/SHA-256 verification');
  }
  await mkdir(dirname(destination), { recursive: true });
  const temporary = `${destination}.${randomUUID()}.download`;
  try {
    await writeFile(temporary, data, { flag: 'wx' });
    // Publish complete verified bytes atomically without overwriting any existing file.
    await link(temporary, destination);
  } finally {
    await unlink(temporary);
  }
  console.log(`Downloaded and verified ${bytes} bytes: ${destination}`);
}

await download();
