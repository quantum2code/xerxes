import type { Check } from '../types.js';
import { header, observation } from './helpers.js';

export const cors: Check = {
  id: 'cors',
  run(page) {
    const origin = header(page, 'access-control-allow-origin').trim();
    const credentials = header(page, 'access-control-allow-credentials').trim() === 'true';
    if (origin === '*' && credentials) return [observation(page, this.id, 'Invalid wildcard credentialed CORS configuration',
      'Browsers reject wildcard origins with credentialed reads. These headers alone do not demonstrate data exposure.',
      'Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true', 'low', ['CWE-942'], 'Allow only explicitly trusted origins; avoid credentialed cross-origin access unless required.')];
    if (origin === 'null' && credentials) return [{ ...observation(page, this.id, 'Credentialed CORS permits null origin',
      'Sandboxed and opaque origins may send Origin: null. Sensitive data exposure requires further authorized verification.',
      'Access-Control-Allow-Origin: null; Access-Control-Allow-Credentials: true', 'medium', ['CWE-942'], 'Do not trust the null origin for credentialed access.'), confidence: 'medium' }];
    if (origin === '*') return [observation(page, this.id, 'Public cross-origin read policy',
      'Wildcard CORS is appropriate for public resources. Sensitivity and exploitability have not been established.',
      'Access-Control-Allow-Origin: *', 'informational', ['CWE-942'], 'Confirm this response is intended for public cross-origin consumption.')];
    return [];
  },
};
