/** Pinned upstream artifact; see models/phishing-url/README.md for provenance and limitations. */
export const PRETRAINED_URL_MODEL = {
  id: 'pirocheto/phishing-url-detection@44f3b19f705b52532e0aadf3d0d15dd892b8a2fb',
  repository: 'https://huggingface.co/pirocheto/phishing-url-detection',
  revision: '44f3b19f705b52532e0aadf3d0d15dd892b8a2fb',
  url: 'https://huggingface.co/pirocheto/phishing-url-detection/resolve/44f3b19f705b52532e0aadf3d0d15dd892b8a2fb/model.onnx',
  sha256: '7ff77a089b1af78dc1d4d8b9056fdbe9b4791a71f7e484e0317655d05f2d22b3',
  bytes: 23_547_864,
  license: 'MIT',
  // Upstream does not publish a training timestamp. Do not substitute the upload date.
  trainedAt: null,
  threshold: 0.5,
} as const;

// Same location for both src/ and dist/ executions; no dependence on process.cwd().
export const DEFAULT_PRETRAINED_MODEL_PATH = new URL(
  '../../../../models/phishing-url/model.onnx', import.meta.url,
);
