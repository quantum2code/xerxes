import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import type { InferenceSession, Tensor } from 'onnxruntime-node';
import { ThreatDetectionModule } from '../contracts/module.js';
import type { ModuleResult } from '../contracts/module-result.js';
import { extractParsedUrlFeatures } from '../shared/url-features.js';
import { parseHttpUrl } from '../shared/url.js';
import { toMlPhishingModuleResult } from './module.js';
import { DEFAULT_PRETRAINED_MODEL_PATH, PRETRAINED_URL_MODEL } from './pretrained-model.js';
import type { MlPhishingAnalyzer, MlPhishingResult } from './types.js';

export interface PretrainedMlPhishingOptions {
  /** Local copy of the pinned artifact. No downloads occur while loading/analyzing. */
  modelPath?: string | URL;
  /** Classification operating point, not a calibration setting. Default: 0.5. */
  threshold?: number;
}

/** Async CPU inference using the upstream graph's own string preprocessing and classifier. */
export class PretrainedMlPhishingModule
  extends ThreatDetectionModule<string, ModuleResult<MlPhishingResult>> implements MlPhishingAnalyzer {
  readonly name = 'mlPhishingDetection';
  private readonly pending = new Set<Promise<InferenceSession.ReturnType>>();
  private closing = false;
  private releasePromise?: Promise<void>;

  private constructor(
    private readonly session: InferenceSession,
    private readonly TensorType: typeof Tensor,
    private readonly threshold: number,
  ) { super(); }

  static async load(options: PretrainedMlPhishingOptions = {}): Promise<PretrainedMlPhishingModule> {
    const threshold = options.threshold ?? PRETRAINED_URL_MODEL.threshold;
    if (!Number.isFinite(threshold) || threshold <= 0 || threshold >= 1) {
      throw new TypeError('Model threshold must be between 0 and 1, exclusive');
    }
    const path = options.modelPath ?? DEFAULT_PRETRAINED_MODEL_PATH;
    if ((await stat(path)).size !== PRETRAINED_URL_MODEL.bytes) {
      throw new Error('Pretrained model size does not match the pinned artifact');
    }
    const bytes = await readFile(path);
    if (bytes.length !== PRETRAINED_URL_MODEL.bytes
      || createHash('sha256').update(bytes).digest('hex') !== PRETRAINED_URL_MODEL.sha256) {
      throw new Error('Pretrained model SHA-256 does not match the pinned artifact');
    }
    // Lazy import keeps the native runtime out of the unconfigured/logistic code path.
    const runtime = await import('onnxruntime-node');
    const session = await runtime.InferenceSession.create(bytes, {
      executionProviders: ['cpu'], intraOpNumThreads: 1, interOpNumThreads: 1,
    });
    return new PretrainedMlPhishingModule(session, runtime.Tensor, threshold);
  }

  async analyze(input: string): Promise<ModuleResult<MlPhishingResult>> {
    if (this.closing) throw new Error('Pretrained ML module is disposed');
    const url = parseHttpUrl(input);
    if (url.username || url.password) throw new TypeError('Pretrained ML input must not contain credentials');
    const features = extractParsedUrlFeatures(url);
    // Validate first, but send the original string to the graph as upstream does. Do not
    // replace its trained preprocessing with the unrelated version-1 numeric features.
    const inference = this.session.run({ inputs: new this.TensorType('string', [input], [1]) });
    this.pending.add(inference);
    try {
      const outputs = await inference;
      const probabilities = outputs.probabilities;
      if (!probabilities || probabilities.type !== 'float32'
        || probabilities.dims.length !== 2 || probabilities.dims[0] !== 1 || probabilities.dims[1] !== 2) {
        throw new Error('Pretrained model returned unexpected probability output');
      }
      // Upstream's documented class ordering is [legitimate (0), phishing (1)].
      const clean = Number(probabilities.data[0]);
      const probability = Number(probabilities.data[1]);
      if (![clean, probability].every((value) => Number.isFinite(value) && value >= 0 && value <= 1)
        || Math.abs(clean + probability - 1) > 1e-5) {
        throw new Error('Pretrained model returned invalid probabilities');
      }
      return toMlPhishingModuleResult(input, {
        status: 'predicted', features, modelId: PRETRAINED_URL_MODEL.id,
        trainedAt: PRETRAINED_URL_MODEL.trainedAt, phishingProbability: probability,
        threshold: this.threshold, prediction: probability >= this.threshold ? 'phishing' : 'not_phishing',
      });
    } finally {
      this.pending.delete(inference);
    }
  }

  /** Stop accepting work, finish in-flight inference, then release native resources. Idempotent. */
  dispose(): Promise<void> {
    this.closing = true;
    this.releasePromise ??= (async () => {
      await Promise.allSettled([...this.pending]);
      await this.session.release();
    })();
    return this.releasePromise;
  }
}

export const loadPretrainedMlPhishingModule = PretrainedMlPhishingModule.load;
