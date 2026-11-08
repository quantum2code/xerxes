import type { ExecutionContext } from '../../pipeline/execution-context.js';
import { parseHttpUrl } from '../../modules/threat-detection/shared/url.js';

export interface ThreatDetectionInput {
  url: string;
}

export interface ValidatedThreatDetectionInput extends ThreatDetectionInput {
  /** Retained to detect spelling/notation that URL serialization would otherwise erase. */
  originalUrl: string;
}

/** Identifies client input failures without mistaking a detector's TypeError for HTTP 400. */
export class InvalidThreatDetectionInputError extends TypeError {}

/** Validate before any detector or external provider is invoked. */
export function handleValidateUrl(context: ExecutionContext): ValidatedThreatDetectionInput {
  return validateThreatDetectionInput(context.input);
}

/** The graph's validation task tags input failures for the HTTP error handler. */
export function validateThreatDetectionInput(input: unknown): ValidatedThreatDetectionInput {
  if (!input || typeof input !== 'object' || Array.isArray(input)
    || !('url' in input) || typeof input.url !== 'string') {
    throw new InvalidThreatDetectionInputError('Threat detection input must be an object with a string url');
  }
  let url: URL;
  try {
    url = parseHttpUrl(input.url);
  } catch (error) {
    throw new InvalidThreatDetectionInputError('Threat detection URL must be a valid explicit HTTP(S) URL', { cause: error });
  }
  // Blacklist providers must never receive embedded credentials; reject before fan-out.
  if (url.username || url.password) throw new InvalidThreatDetectionInputError('Threat detection URLs must not contain credentials');
  return { url: url.href, originalUrl: input.url };
}

/** Detector tasks must declare validateUrl as a dependency rather than rereading unvalidated input. */
export function getValidatedUrl(context: ExecutionContext, representation: 'normalized' | 'original' = 'normalized'): string {
  const result = context.results.validateUrl;
  if (!result || typeof result !== 'object' || !('url' in result) || typeof result.url !== 'string') {
    throw new Error('Missing validateUrl result; the handler requires a successful validateUrl dependency');
  }
  if (representation === 'original') {
    if (!('originalUrl' in result) || typeof result.originalUrl !== 'string') {
      throw new Error('Missing validateUrl originalUrl; the handler requires the original validated input');
    }
    return result.originalUrl;
  }
  return result.url;
}
