import type { UrlFeatureName, UrlFeatures } from '../shared/url-features.js';
import type { ModuleResult } from '../contracts/module-result.js';

/** Preloaded ML implementation accepted by Engine 1; may perform asynchronous local inference. */
export interface MlPhishingAnalyzer {
  readonly name: 'mlPhishingDetection';
  analyze(input: string): ModuleResult<MlPhishingResult> | Promise<ModuleResult<MlPhishingResult>>;
}

export interface LogisticUrlModel {
  format: 'xerxes-url-logistic-v1';
  id: string;
  trainedAt: string;
  featureNames: readonly UrlFeatureName[];
  /** Standardization learned on the training set, not on the URL being analyzed. */
  means: readonly number[];
  scales: readonly number[];
  weights: readonly number[];
  intercept: number;
  threshold: number;
}

export type MlPhishingResult = {
  status: 'not_configured';
  features: UrlFeatures;
  modelId: null;
  phishingProbability: null;
  prediction: null;
} | {
  status: 'predicted';
  features: UrlFeatures;
  modelId: string;
  /** Null when the pretrained model's author does not provide a training date. */
  trainedAt: string | null;
  phishingProbability: number;
  threshold: number;
  prediction: 'phishing' | 'not_phishing';
};
