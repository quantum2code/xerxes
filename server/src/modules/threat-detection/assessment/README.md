# Simple evidence and threat assessment

Detectors collect observations. Rules interpret them. One assessment class produces the report. There is no evidence-collector class, weighted score, external service, or LLM.

## Module output

All five detector classes and their DAG handlers now return:

```ts
interface ModuleResult<TDetails> {
  module: DetectorModule;
  status: 'completed' | 'partial' | 'not_configured' | 'error';
  evidence: Evidence[];
  details: TDetails;
  issues: string[];
}
```

- `completed`: configured checks completed, not proof of safety or accuracy.
- `partial`: useful observations exist but one or more checks failed or traversal stopped early.
- `not_configured`: no ML model, brand catalog, or nonempty blacklist source.
- `error`: operational inspection failed without a completed check.

`details` preserves the previous detector output, including its original status semantics. It can contain full URLs, credentials, queries, raw Location headers, or provider diagnostics and should not be indiscriminately exposed/logged. Evidence uses hostnames, fixed observation fields, and known matched terms; the default assessment report does not copy raw URLs or diagnostics.

Invalid input/configuration and unexpected programming exceptions still throw. The DAG's validation task rejects credential-bearing inputs and malformed URLs before detector work starts. Existing network/provider errors are represented as module results so the final task can report incomplete coverage rather than being blocked by expected operational failures.

## Evidence codes

`Evidence` is a discriminated TypeScript union. Every observation identifies its originating `module`, normalized `hostname`, and `target: 'submitted' | 'redirect'`:

| Code | Observed fields |
| --- | --- |
| `URL_STRUCTURE` | Structural signal, component, measured value, optional threshold |
| `AUTH_KEYWORD` | URL component and matched authentication/account-related terms |
| `REDIRECT_HOP` | Destination hostname, originating hostname/scheme, target scheme, cross-domain flag, followed flag |
| `BLACKLIST_MATCH` | Source name and whether it is a snapshot/provider |
| `ML_PREDICTION` | Estimated probability, configured threshold, model ID/training date |
| `BRAND_LOOKALIKE` | Brand, resemblance reason, official domains, optional edit distance |

No evidence includes threat severity. ML probabilities/predictions and brand resemblance remain detector observations, not security verdicts. Redirect evidence can identify a target that was observed in Location but never requested; `followed` makes this distinction explicit.

## Assessment

```ts
import {
  BasicUrlAnalysisModule,
  BrandImpersonationModule,
  ThreatAssessment,
} from './modules/threat-detection/index.js';

const url = 'https://paypaal.com/login';
const report = new ThreatAssessment().assess([
  new BasicUrlAnalysisModule().analyze(url),
  new BrandImpersonationModule([
    { name: 'PayPal', domains: ['paypal.com'] },
  ]).analyze(url),
]);
// A medium-severity possible-impersonation finding, with its evidence attached.
// Missing redirect/blacklist/ML results are listed in incompleteModules.
```

`ThreatAssessment` also implements the generic module contract through `analyze(results)`, an alias for `assess(results)`. Results passed to a single assessment must come from one submitted-URL analysis; do not merge unrelated runs. Duplicate module results and mismatched evidence origin identifiers are rejected. The assessor expects all five Engine 1 detectors, and explicitly lists omitted ones as `missing`.

The report contains:

```ts
{
  policyVersion: 'simple-v1',
  riskLevel: 'unknown' | 'low' | 'medium' | 'high',
  summary: string,
  findings: [{ ruleId, severity: 'info' | 'medium' | 'high', message, evidence }],
  incompleteModules: [{ module, status, issues }],
}
```

Overall risk is the highest medium/high finding, without adding arbitrary points. When only informational/no findings exist, incomplete coverage produces `unknown`; all five completed checks produce `low`, explicitly **not a safety guarantee**. Positive findings survive missing or failed checks: high risk with incomplete coverage is possible and is disclosed in the summary and module list.

## Default rules

| Rule | Behavior |
| --- | --- |
| `blacklist-match` | Trusted source match: high; other configured source match: medium. Matches for the same hostname/target are grouped. |
| `brand-impersonation` | Brand resemblance alone: info. Authentication terms in the path/query or an above-threshold model estimate on the same hostname/target: medium. |
| `redirect-behavior` | HTTPS-to-HTTP target: medium transport-security finding, not a phishing verdict. Other cross-domain hops: info. |
| `url-structure` | Embedded credentials: medium. Other structural/keyword observations: info, never accumulated into a high rating. |
| `ml-signal` | Above-threshold model estimate: info by itself. When brand evidence exists it is considered by the brand rule instead. |

Rules group related observations rather than counting each as independent proof. Punycode and authentication observations already used with brand resemblance are not separately elevated. Corroboration requires both the same hostname **and** the same submitted/redirect target kind.

Blacklist trust is explicit:

```ts
import { createAssessmentRules, ThreatAssessment } from './modules/threat-detection/index.js';

const assessment = new ThreatAssessment(createAssessmentRules({
  trustedBlacklistSources: ['application-managed-feed'],
}));
```

No source is trusted by default. Trust configuration does **not** verify feed correctness, freshness, or provider reliability: maintain/update feeds and evaluate source quality before granting trust. Snapshot timestamps remain in raw blacklist diagnostics. Likewise, synthetic test models do not establish ML accuracy or calibration. These are baseline, reviewable rules—not a claim of validated phishing-detection performance.

Custom rules are plain objects with unique IDs and `evaluate(evidence): Finding[]`. A rule may return multiple findings for different targets. Pass them into `new ThreatAssessment(rules, 'your-policy-version')`; each finding must reference its rule's ID. Rules are trusted application code, not untrusted JSON or executable user input.

## DAG integration and migration

`buildThreatDetectionPipeline()` now ends with `threatAssessment`, depending on all five detector tasks. No runner/scheduler changes were required. Configure trust through:

```ts
const dag = buildThreatDetectionPipeline({
  // Existing redirects, mlModel, blacklist, brandImpersonation configuration...
  assessment: { trustedBlacklistSources: ['application-managed-feed'] },
});
const results = await new PipelineRunner(dag).run({ url: 'https://example.com' });
const report = results.threatAssessment;
```

Migration changes:

- Class/DAG outputs: `result.hostname` becomes `result.details.hostname`, etc.
- Module `status` is execution/coverage status; raw detector-specific status is under `details.status`.
- Basic URL signals no longer expose `severity`; the final report assigns finding severity.
- Functional analyzer APIs still return raw diagnostics without wrapping them.
- `POST /api/analyze` now runs the real DAG and returns these module envelopes plus `threatAssessment`, replacing the legacy mock HTTP results.

Tests are offline: `test/threat-assessment.test.ts` covers rule matching, provenance, target isolation, incomplete checks, trust configuration, low-risk wording, privacy, model support, redirects, custom rules, and final DAG output.
