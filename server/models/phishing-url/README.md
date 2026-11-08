# Opt-in pretrained URL phishing model

## Model selection and provenance

Selected **[pirocheto/phishing-url-detection](https://huggingface.co/pirocheto/phishing-url-detection)**,
published by Hugging Face user **pirocheto**. Upstream describes it as a **Linear SVM**
for binary URL classification, with ONNX input-string preprocessing and probability
outputs. This is a real published trained model, not heuristic/synthetic coefficients.
The complete upstream graph is used unchanged: its weights are **not** mapped onto
Xerxes's unrelated 18-feature logistic contract.

- Model revision: `44f3b19f705b52532e0aadf3d0d15dd892b8a2fb`
- Artifact: [`model.onnx`](https://huggingface.co/pirocheto/phishing-url-detection/resolve/44f3b19f705b52532e0aadf3d0d15dd892b8a2fb/model.onnx)
- Bytes: `23,547,864` (~22.5 MiB)
- SHA-256: `7ff77a089b1af78dc1d4d8b9056fdbe9b4791a71f7e484e0317655d05f2d22b3`
- License declared by author: **[MIT](https://opensource.org/license/mit)**; see `LICENSE`.
- Model card retained verbatim as `UPSTREAM_MODEL_CARD.md`.
- Integration/retrieval date: **2026-11-08**.
- Hub revision last-modified date: 2023-12-01. **Training date is not published**;
  results/evidence use `trainedAt: null`, not an invented date.
- Linked training dataset: [pirocheto/phishing-url](https://huggingface.co/datasets/pirocheto/phishing-url)
  (declared CC BY 4.0; based on the phishing-detection benchmark of Hannousse and
  Yahiouche, [arXiv:2010.12847](https://arxiv.org/abs/2010.12847)). No training data
  or site contents are downloaded or redistributed by this integration.

This candidate has an explicit model license, a raw-URL interface, and a published
Node.js/ONNX usage example. It avoids untrusted Python pickle/joblib deserialization,
Python serving infrastructure, retraining, and hand-porting feature extraction.
The MIT model license and any underlying dataset/source licenses are distinct.

## Installation and use

From `server/`:

```sh
pnpm install
pnpm ml:download
```

The explicit download command retrieves **only** the pinned ONNX artifact from
Hugging Face, verifies byte count and SHA-256, and publishes it without overwriting
an existing file. A valid existing file is reused; an invalid existing file fails
and must be deliberately removed/replaced. Downloaded `.onnx` files are gitignored.
Package installation does not download the model. Deployments must provision the
verified file themselves, or run the command during their build/setup phase.
For offline deployments, copy the verified artifact to this directory or pass its
local path to the loader. No pickle, website archive, or training dataset is needed.

```ts
import { loadPretrainedMlPhishingModule } from './src/modules/threat-detection/ml-phishing/index.js';
import { buildThreatDetectionPipeline } from './src/pipelines/threat-detection-pipeline.js';
import { PipelineRunner } from './src/pipeline/pipeline-runner.js';

const mlModule = await loadPretrainedMlPhishingModule();
// Optional: { modelPath: '/srv/models/model.onnx', threshold: 0.8 }
try {
  const standalone = await mlModule.analyze('https://example.com/');
  const runner = new PipelineRunner(buildThreatDetectionPipeline({ mlModule }));
  const results = await runner.run({ url: 'https://example.com/' });
} finally {
  await mlModule.dispose();
}
```

Load once at application startup, reuse across requests, and dispose on shutdown.
The loader checks size/hash before initializing ONNX Runtime. Missing/corrupt files
or initialization failures reject; there is no download, fallback score, or silent
`not_configured` result. Invalid input and unexpected inference failures also reject.
`dispose()` is idempotent, blocks new work, and waits for in-flight inference before
releasing native resources. Each call has its own input tensor and result state.

ONNX Runtime **1.31.1** runs locally with the CPU execution provider and one intra-op
and inter-op thread per session. Its native package is substantially larger than the
model (~308 MB unpacked, across bundled platforms). CPU binaries are bundled; pnpm's
build-script policy explicitly disables optional install-time CUDA downloads.
The native runtime is imported lazily only when loading a verified pretrained model.
Supported platforms are those supported by `onnxruntime-node`; this integration was
validated on Linux x64/Node 22+.

The default file resolves relative to source/compiled code, not the current working
directory, so `pnpm build` works without copying assets into `dist/`. Deployment
must retain `models/phishing-url/model.onnx` beside `dist/`, or use `modelPath`.

`mlModel` still accepts the existing synchronous `LogisticUrlModel`. `mlModule`
accepts a preloaded implementation of `MlPhishingAnalyzer`. Supplying both is an
error. Without either option, ML still returns `not_configured`. Library/pipeline
defaults do not automatically enable this model. The standard HTTP entry point
explicitly loads it before listening and supplies it to `/api/analyze`; startup
fails if the verified file is unavailable. Set `PHISHING_ONNX_MODEL_PATH` to use
a different local copy of the same pinned artifact.

## Input/output contract

- Strict explicit HTTP(S) URLs only, at most 8,192 characters; no whitespace,
  malformed hosts, parser-repair syntax, or embedded credentials.
- The validated input string is supplied to ONNX as `inputs`, a one-dimensional
  string tensor of shape `[1]`. The graph handles its own trained preprocessing.
  Standalone inference preserves that string. The existing DAG passes its validated,
  serialized URL; spelling/normalization changes can change model estimates.
- `probabilities` is a float32 tensor of shape `[1, 2]`; the author's documented
  class order is **0 = legitimate, 1 = phishing**. The second value is returned as
  `phishingProbability`; both values/ranges and their sum are validated.
- The default classification threshold is **0.5**, an explicit conventional
  operating point, not a claimed deployment-tuned/calibrated threshold. Callers
  may choose another finite threshold strictly between 0 and 1.
- Diagnostics retain the existing 18 URL `features` for API compatibility. They
  are **not** the inputs/feature explanations of this SVM and must not be interpreted
  as learned feature contributions.
- Results use the existing `ModuleResult<MlPhishingResult>` envelope and emit
  `ML_PREDICTION` evidence with the pinned model ID and unknown training date.
  Existing assessment rules remain unchanged; ML alone is not a high-risk verdict.
- No URL is submitted to Hugging Face or fetched for inference. Only the explicit
  setup command contacts Hugging Face. Engine 1's separate redirect task still
  performs network I/O unless an offline transport is injected.

## Evaluation and limitations

The upstream model card reports ROC-AUC **0.986844**, accuracy **0.948568**, F1
**0.948623**, precision **0.947619**, and recall **0.949629**. These are **author-reported
historical results**, not independently reproduced or representative production
guarantees. The card does not adequately document temporal/domain isolation,
calibration, a complete training recipe, or training timestamp.

The integration tests verify deterministic local inference and the author's two
example URLs, not real-world model quality. An old lexical URL classifier can miss
compromised legitimate hosts, shorteners, new campaigns, and content-only attacks;
it may flag legitimate unusual URLs. The balanced research data does not reflect
real-world phishing prevalence, and scores are not calibrated safety guarantees.
Before production, evaluate recent labeled data with domain/time-isolated splits,
measure false positives/negatives, choose an operating point for your application,
and establish refresh/monitoring procedures. Never treat `not_phishing` as safe.

## Tests (no network)

```sh
pnpm exec tsx --test test/ml-phishing-pretrained.test.ts test/threat-detection.test.ts test/threat-detection-pipeline.test.ts
pnpm typecheck
pnpm build
```

Loader validation and injected-module tests always run offline. Real-model tests
run when the default local artifact exists; otherwise they are explicitly skipped.
Provision the artifact first to run them, or set `PHISHING_MODEL_TEST_PATH` to a
verified local copy (an explicitly configured missing/bad path fails rather than
skipping). No test downloads anything or visits the example URLs. Numerical
regressions use probabilities observed from the pinned upstream graph, with a
small float32 tolerance; these are inference parity checks, not accuracy claims.
