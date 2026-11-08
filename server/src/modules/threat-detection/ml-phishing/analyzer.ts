import { extractUrlFeatures, URL_FEATURE_NAMES } from '../shared/url-features.js';
import type { LogisticUrlModel, MlPhishingResult } from './types.js';

export type { LogisticUrlModel, MlPhishingResult } from './types.js';

function finiteVector(value: unknown, name: string): number[] {
  if (!Array.isArray(value) || value.length !== URL_FEATURE_NAMES.length
    || !value.every((entry) => typeof entry === 'number' && Number.isFinite(entry))) {
    throw new TypeError(`${name} must contain ${URL_FEATURE_NAMES.length} finite numbers`);
  }
  return [...value];
}

/** Validates a loaded JSON artifact and copies its parameters to isolate subsequent inference. */
export function validateLogisticUrlModel(input: unknown): LogisticUrlModel {
  if (!input || typeof input !== 'object') throw new TypeError('Model must be an object');
  const model = input as Record<string, unknown>;
  if (model.format !== 'xerxes-url-logistic-v1') throw new TypeError('Unsupported URL model format');
  if (typeof model.id !== 'string' || !model.id.trim()) throw new TypeError('Model id is required');
  if (typeof model.trainedAt !== 'string' || !Number.isFinite(Date.parse(model.trainedAt))) {
    throw new TypeError('Model trainedAt must be a valid date string');
  }
  const featureNames = model.featureNames;
  if (!Array.isArray(featureNames) || featureNames.length !== URL_FEATURE_NAMES.length
    || !URL_FEATURE_NAMES.every((name, index) => featureNames[index] === name)) {
    throw new TypeError('Model featureNames must exactly match URL_FEATURE_NAMES in order');
  }
  const means = finiteVector(model.means, 'means');
  const scales = finiteVector(model.scales, 'scales');
  const weights = finiteVector(model.weights, 'weights');
  if (scales.some((scale) => scale <= 0)) throw new TypeError('Model scales must be positive');
  if (typeof model.intercept !== 'number' || !Number.isFinite(model.intercept)) {
    throw new TypeError('Model intercept must be finite');
  }
  if (typeof model.threshold !== 'number' || !Number.isFinite(model.threshold)
    || model.threshold <= 0 || model.threshold >= 1) {
    throw new TypeError('Model threshold must be between 0 and 1, exclusive');
  }
  return {
    format: 'xerxes-url-logistic-v1', id: model.id, trainedAt: model.trainedAt,
    featureNames: [...URL_FEATURE_NAMES], means, scales, weights,
    intercept: model.intercept, threshold: model.threshold,
  };
}

/**
 * Local logistic-regression inference with a supplied trained artifact. The optional
 * upstream ONNX model has a separate async loader; it does not use this feature contract.
 * Probabilities are model estimates, not calibrated guarantees; validate on held-out, recent URLs.
 */
export function createMlPhishingDetector(artifact?: unknown): (input: string) => MlPhishingResult {
  const model = artifact === undefined ? undefined : validateLogisticUrlModel(artifact);
  return (input) => {
    const features = extractUrlFeatures(input);
    if (!model) {
      return { status: 'not_configured', features, modelId: null, phishingProbability: null, prediction: null };
    }
    let logit = model.intercept;
    URL_FEATURE_NAMES.forEach((name, index) => {
      logit += ((features[name] - model.means[index]!) / model.scales[index]!) * model.weights[index]!;
    });
    if (!Number.isFinite(logit)) throw new RangeError('Model parameters produced a non-finite logit');
    // Stable sigmoid avoids exp overflow for large negative logits.
    const probability = logit >= 0 ? 1 / (1 + Math.exp(-logit)) : Math.exp(logit) / (1 + Math.exp(logit));
    return {
      status: 'predicted', features, modelId: model.id, trainedAt: model.trainedAt,
      phishingProbability: probability, threshold: model.threshold,
      prediction: probability >= model.threshold ? 'phishing' : 'not_phishing',
    };
  };
}
