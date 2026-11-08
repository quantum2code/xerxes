# Engine 1: independent threat-detection modules

These modules do not require the DAG runner, Express, or each other's analysis results. Import them individually or from `index.ts`. To run all five as a DAG, use [`buildThreatDetectionPipeline`](../../pipelines/threat-detection-pipeline.ts) and its dedicated [`task handlers`](../../tasks/threat-detection/index.ts); see the [Engine 1 DAG guide](../../../README.md#engine-1-dag-and-handlers). Validation runs first, followed by five independent handlers analyzing the submitted URL concurrently, then a final rule-based threat assessment. `POST /api/analyze` now runs this graph. The standard server entry point explicitly selects the pretrained model and Zenodo catalog; library defaults remain unconfigured. See the [HTTP contract](../../../README.md#http-analysis-contract).

## Module contract and layout

All five detectors extend the same generic class, [`ThreatDetectionModule<TInput, TOutput>`](contracts/module.ts):

```ts
abstract class ThreatDetectionModule<TInput, TOutput> {
  abstract readonly name: string;
  abstract analyze(input: TInput): TOutput | Promise<TOutput>;
}
```

The base class defines an execution contract, not a common risk score or verdict. Each detector class returns `ModuleResult<TDetails>` with `{ module, status, evidence, details, issues }`, preserving its typed diagnostics under `details` and its sync/async behavior. Evidence codes are observations, not severity judgments. The final [`ThreatAssessment`](assessment/README.md) class applies plain rules and produces the report. Configuration is supplied through constructors, and the DAG's thin handlers adapt execution-context input to `analyze()`. Existing function APIs remain exported through each module's `index.ts` and the root `index.ts`.

```text
threat-detection/
  contracts/module.ts        Generic base class
  contracts/evidence.ts      Typed evidence codes and source/target attribution
  contracts/module-result.ts Execution status, evidence, and raw diagnostics
  shared/
    url.ts                   Shared strict URL parser and domain helpers
    url-features.ts          Unchanged version-1 lexical feature definitions
  basic-url-analysis/
  http-redirect/
  ml-phishing/
  blacklist/
  brand-impersonation/
    types.ts                 Detector-specific contracts
    analyzer.ts              Functional implementation
    module.ts                Concrete class/configuration boundary
    index.ts                 Public exports
  assessment/                Report types, plain rules, and ThreatAssessment class
  index.ts                   Public exports for all modules
```

Every detector directory follows the four-file pattern shown under `brand-impersonation/`. Prefer public `index.ts` imports rather than reaching into `analyzer.ts`. The previous flat implementation paths have moved; imports through the root index retain the same function names.

Maintenance boundaries:

- `shared/url.ts` owns strict parsing and canonical reputation keys; already-parsed
  URLs can be normalized without repeating validation. Keep standalone public API
  validation even when the DAG also validates its input.
- `validateUrl` is the HTTP/DAG validation boundary. Its typed input errors map to
  HTTP 400; a detector's unrelated `TypeError` remains an unexpected HTTP 500.
- Google providers share credential/transport/JSON-envelope handling in
  `blacklist/google-provider.ts`, but retain separate service-specific response parsers.
- `DETECTOR_MODULES` defines fan-out task names/order and the assessment join;
  the graph's handler map is typechecked against those names.
- The compiler rejects unused local declarations and parameters. Exported
  alternatives remain supported APIs, not dead code merely because startup selects
  Safe Browsing. No refactor should remove SSRF, credential, or response-schema guards.

```ts
import { BasicUrlAnalysisModule } from './modules/threat-detection/index.js';

const module = new BasicUrlAnalysisModule();
const result = module.analyze('https://example.com/login');
// Synchronous ModuleResult<BasicUrlAnalysis>.
// result.evidence contains observations; result.details contains raw URL analysis.
```

Concrete classes are `BasicUrlAnalysisModule`, `HttpRedirectModule`, `MlPhishingModule`, `BlacklistModule`, and `BrandImpersonationModule`. This organization does not imply that the four non-basic detectors have completed a production audit.

## Approach and libraries

| Module | Implementation | Library/runtime |
| --- | --- | --- |
| `http-redirect/` | Follow HTTP 301/302/303/307/308 `Location` headers; record chain, cross-domain changes, downgrades, loops, limits, and failures | Node HTTP/HTTPS, DNS, `ipaddr.js`, `tldts` |
| `basic-url-analysis/` | Structural URL indicators and lexical measurements, with explanatory findings rather than a fabricated risk score | WHATWG `URL`, `tldts` |
| `ml-phishing/` | Caller-supplied logistic regression or opt-in pretrained URL Linear SVM | Pure TypeScript for logistic artifacts; local CPU ONNX Runtime for the pretrained graph |
| `blacklist/` | Exact URL/domain snapshots; Google Safe Browsing, optional Web Risk/PhishTank, or custom providers | Node URL/IDNA, `tldts`, fetch/HTTPS, `AbortController` |
| `brand-impersonation/` | Official-domain recognition, edit-distance typos, Unicode lookalikes, brand-containing domains, deceptive subdomains | `tldts`, `fastest-levenshtein`, `confusables`, Node IDNA |

`tldts` includes the Public Suffix List and uses private suffixes too: `tenant.github.io` is a distinct registrable domain. Keep dependencies updated as suffix data changes. No external service, API key, model download, blacklist feed download, or browser is enabled by default.

## Usage

From another file under `src/`:

```ts
import {
  analyzeBasicUrl,
  createBlacklistChecker,
  createBrandImpersonationDetector,
  createMlPhishingDetector,
  detectHttpRedirects,
} from './modules/threat-detection/index.js';

const url = 'https://paypal.com.attacker.example/login';

const basic = analyzeBasicUrl(url);
const detectBrand = createBrandImpersonationDetector([
  { name: 'PayPal', domains: ['paypal.com', 'paypal.co.uk'] },
]);
const brand = detectBrand(url);

const checkBlacklist = createBlacklistChecker({
  snapshots: [{
    source: 'application-managed-feed',
    updatedAt: '2026-11-01T00:00:00Z',
    domains: ['known-bad.example'],
    urls: ['https://another.example/phishing?campaign=1'],
  }],
});
const blacklist = await checkBlacklist(url);

const detectMl = createMlPhishingDetector();
const ml = detectMl(url); // status: 'not_configured', no probability or prediction

// Explicit opt-in network operation; contacts the submitted public site.
const redirects = await detectHttpRedirects(url, {
  maxRedirects: 10,
  timeoutMs: 5_000,
});
```

Catalog domains must be official **registrable domains**, not bare suffixes or subdomains. List legitimate regional/alternate domains to avoid false positives. There is no default catalog. An empty catalog reports `brandsChecked: 0` and cannot detect impersonation. An official domain suppresses findings only for its own brand. Brand checks inspect the hostname, not the path or query. Default typo distance is 1 (configurable to 2); typo checks skip labels shorter than 5 characters, and brand-containing checks skip tokens shorter than 4. These are conservative heuristics, not comprehensive brand protection or Unicode security validation.

### HTTP redirects and network safety

`detectHttpRedirects()` returns:

- `status`: `complete | blocked | loop | limit | error`.
- `chain`: `{ url, statusCode, location, redirect? }[]`, preserving raw Location values. A valid HTTP(S) redirect includes `{ url, crossDomain, followed }` destination metadata, even when safety, loop, or limit checks stop traversal. `followed` is true only when the destination returned a valid HTTP response; merely pointing to an earlier hop does not count.
- `finalUrl`: last attempted target, which may be blocked and never requested.
- `crossDomain`, `httpsDowngrade`: signals accumulated over observed redirects, including blocked targets.
- `error`: `{ code, message }` or `null`.

A completed chain is not a safety verdict or a guarantee of a 2xx response. Only HTTP redirects are inspected, not JavaScript, HTML meta-refresh, or page content. Each hop uses GET and closes the request after response headers without intentionally reading/buffering the body. GET still contacts the site and may trigger server-side behavior.

Defaults: 10 redirects, 5000 ms per hop, with configuration bounds of 0–50 redirects and 1–120000 ms per hop. The initial request does not count as a redirect. Each deadline covers DNS and HTTP together; the maximum total wait grows with the hop count.

The default transport rejects credentials and non-default ports, validates **all** DNS answers as public unicast addresses, blocks IP literals in nonpublic ranges (including mapped IPv4), and pins the socket to a validated address. TLS verification remains enabled for the original hostname, and no cookies or authorization headers are forwarded. Private, loopback, link-local, reserved, and other non-unicast destinations are blocked at every hop. Keep production egress restrictions too: application checks are not a replacement for network isolation and rate/concurrency limits.

`transport` is a **trusted injection boundary** that bypasses default DNS/IP protections. `createSafeHttpRedirectTransport({ lookup, request })` exposes narrower trusted seams for testing. A custom transport/provider must honor its AbortSignal to release its own resources; deadlines bound waiting even if it ignores cancellation. Uncancellable DNS may finish later, but its late result cannot create a socket after the deadline.

### Basic analysis

`analyzeBasicUrl()` returns normalized/Unicode hostnames, registrable domain, suffix, subdomain, numeric `features`, a credential-redacted `displayUrl`, and explanatory `signals`. `BasicUrlAnalysisModule.analyze()` wraps that result under `.details` and emits `URL_STRUCTURE` / `AUTH_KEYWORD` evidence. Each raw signal includes `code`, `location`, `description`, and structural `evidence`, but no threat severity. Keyword observations report matched terms per hostname/path/query/fragment and decode percent escapes once where valid; credentials are not searched for keyword evidence. Assessment rules, not detectors, assign severity. Numeric ML features retain their version-1 definitions and do not adopt this decoded/component-specific keyword behavior.

Signals include HTTP, IP hosts, user information, punycode, non-default ports, URL length over 200, at least three subdomain labels/hyphens, at least five percent encodings, single-label/local hostnames, and unusual IPv4 notation such as decimal integers, hexadecimal, octal, or shortened addresses. Neither local-host indicators nor IP indicators perform DNS or network checks. Legitimate URLs can trigger any signal, and HTTPS or an absence of signals does not establish safety.

See the [basic URL contract and examples](basic-url-analysis/README.md) for validation rules, privacy limitations, and detailed behavior.

### Blacklists

`createBlacklistChecker({ snapshots?, providers?, timeoutMs? })` returns an asynchronous checker. Snapshots are copied at construction; instantiate a new checker when refreshing a feed. Feed acquisition, source trust, licensing, and freshness enforcement belong to the caller. Results expose snapshot timestamps but do not reject stale feeds automatically.

- `matched`: one or more sources matched, even if other providers failed.
- `no_match`: configured sources completed without matching; **not** a benign verdict.
- `unknown`: no configured sources, or at least one provider failed and none matched.

Results include `matches`, `checkedSources`, `errors`, and `snapshots`. Source lists include attempted providers even when they fail. A domain snapshot entry matches itself and its subdomains at label boundaries; IP entries match only that IP. Bare public/private suffix entries, malformed hostnames, wildcards, and URL syntax in domain entries are rejected. URL entries drop fragments and normalize via WHATWG URL serialization but preserve path case and query order. Equivalent application-specific URLs are not necessarily equivalent keys.

#### Google Safe Browsing provider

The standard non-commercial HTTP server uses `createGoogleSafeBrowsingProvider({ apiKey })`.
Enable `safebrowsing.googleapis.com` and set `GOOGLE_SAFE_BROWSING_API_KEY` in
`server/.env`; `pnpm dev`/`pnpm start` load it. Missing keys leave blacklist checks
explicitly unconfigured. The old `GOOGLE_WEB_RISK_API_KEY` is a migration alias only;
an existing key needs to allow Safe Browsing in its API restrictions. No call goes
to Web Risk or PhishTank during normal server analysis.

The provider sends one canonical URL via JSON POST to
`https://safebrowsing.googleapis.com/v4/threatMatches:find` with the key in
`x-goog-api-key`. It requests `SOCIAL_ENGINEERING`, `MALWARE`, `UNWANTED_SOFTWARE`,
`ANY_PLATFORM`, and `URL`. Google receives the URL including path/query, not fragments.
An empty object/empty matches array is a completed negative, not a safety guarantee.
Matches must have requested threat categories, valid platform/entry selectors, the
queried URL, and a valid cache duration. Malformed, mismatched, error, quota/auth,
and timeout responses are inconclusive. The checker propagates abort signals.

`addressFamily?: 4 | 6` (server environment `GOOGLE_SAFE_BROWSING_ADDRESS_FAMILY`)
selects a native HTTPS transport for the fixed Google endpoint. It preserves TLS,
refuses redirects, and never changes global fetch/DNS or the redirect detector's
SSRF protections. The legacy `GOOGLE_WEB_RISK_ADDRESS_FAMILY` is also a migration
alias. A trusted `fetch` replacement takes precedence for offline tests.

```ts
const provider = createGoogleSafeBrowsingProvider({ apiKey: 'server-owned-key' });
const check = createBlacklistChecker({ providers: [provider], timeoutMs: 5_000 });
```

There is no caching, retrying, Google SDK dependency, or URL Submission API. Positive
match details use "potentially unsafe" and contain the required linked **Advisory
provided by Google** plus educational URLs. Consumers must render these only for
Google-matched warnings, give the protection-imperfection notice before users enable
protection, and obey Google's non-commercial, quota, warning, and cache-duration
requirements. See [HTTP setup and display obligations](../../../README.md#google-safe-browsing-server-configuration).

#### Google Web Risk provider (optional library alternative)

The billing-enabled Web Risk provider remains available to independent callers but
is no longer registered by HTTP server startup. To use it explicitly:

```ts
import { createBlacklistChecker, createGoogleWebRiskProvider } from './modules/threat-detection/index.js';

const apiKey = process.env.GOOGLE_WEB_RISK_API_KEY;
const check = createBlacklistChecker({
  providers: apiKey === undefined ? [] : [createGoogleWebRiskProvider({ apiKey })],
  timeoutMs: 5_000,
});
const result = await check('https://example.com/');
```

Enable `webrisk.googleapis.com` in a Google Cloud project and configure a restricted
API key/billing. `pnpm dev`/`pnpm start` load `server/.env` if present; exported
variables take precedence. Restart after changing `.env`. Server startup interprets
legacy Web Risk environment names as Safe Browsing aliases; use an explicit provider
configuration to actually call Web Risk. Keys never come from request bodies.

The provider sends a canonical URL (including path/query, excluding fragments)
to `https://webrisk.googleapis.com/v1/uris:search` via GET with repeated `threatTypes`
parameters: `SOCIAL_ENGINEERING`, `MALWARE`, `UNWANTED_SOFTWARE`. The API key is sent
in `x-goog-api-key`, not the URL. Google receives the full queried URL; do not submit
private tokens inadvertently. It checks the submitted URL, not redirect destinations.

Only the documented empty JSON object is a completed negative. Matches require
nonempty known threat enums and a valid expiration timestamp; only validated enum
names enter match details. Unknown/error/malformed payloads, failed HTTP requests,
auth/quota failures, and timeouts are inconclusive. Keys, response bodies, and raw
network errors are not echoed. Redirects are refused, the checker deadline/AbortSignal
is forwarded, and results are not cached or retried. `no_match` is not a safety verdict.

The provider implements the existing `BlacklistProvider` contract; no Google SDK,
new dependency, ADC, training data, or Web Risk Submission API is involved. It also
accepts a trusted `fetch` replacement for offline tests. Respect Google's pricing,
display/redistribution requirements, and cache-expiration rules if adding caching.
See [Google's Web Risk pricing](https://cloud.google.com/web-risk/pricing).

#### PhishTank provider

PhishTank is opt-in at the library level; creating a checker or graph without a
`providers` list does not enable it. The standard HTTP server uses Google Safe Browsing
instead and does not read `PHISHTANK_*` variables. No service
credentials are bundled, and the provider factory itself does not read environment
variables automatically. Absent keys use keyless access.

```ts
import {
  createBlacklistChecker, createPhishTankProvider,
} from './modules/threat-detection/index.js';


const phishTankKey = process.env.PHISHTANK_API_KEY;
const providers = [

  createPhishTankProvider({
    ...(phishTankKey ? { apiKey: phishTankKey } : {}),
    userAgent: 'phishtank/xerxes',
  }),
];
const blacklist = { providers, timeoutMs: 5000 };
const checker = createBlacklistChecker(blacklist);
const result = await checker('https://example.com/');
// The same blacklist options work with new BlacklistModule(blacklist)
// or buildThreatDetectionPipeline({ blacklist }).
```


- **PhishTank** (`phishtank`): posts form-encoded lookups to the [URL-check API](https://www.phishtank.com/api_info.php). An API key is optional, but keyless requests have lower limits. Supply a descriptive `userAgent`, preferably `phishtank/` followed by your registered username; the default is `phishtank/xerxes`. Matches require an in-database, verified, valid phishing entry. Unverified entries produce incomplete coverage; an absent entry or a verified non-phishing entry does not match. Both documented `y`/`n` flags and boolean flags are accepted.

The provider uses a fixed HTTPS endpoint, rejects HTTP redirects, and forwards the checker's AbortSignal to native `fetch`. HTTP authentication failures, rate limits (429/509), invalid JSON/schema responses, and network errors are reported as provider errors. Raw response bodies, network error causes, API keys, and checked URLs are not included in its error messages. There are no automatic retries, caches, or background refreshes: every check consumes a request per configured service. Observe account quotas, service terms, and licensing; implement application-level throttling before using these for high-volume traffic. The provider is not implicitly trusted by assessment policy. Explicitly configure `trustedBlacklistSources: ['phishtank']` only if that matches your application's trust policy.

A provider receives the **full URL including the query**, which may expose tokens or personal information to a third party. Configure a trusted service deliberately and hold API keys in server-side environment configuration, never in client bundles or source control. Credential-bearing URLs are rejected before any request. Provider calls run concurrently with independent bounded deadlines (default 5000 ms); errors/timeouts are reported separately rather than interpreted as no matches. Independent `createApp(options)` callers supply their own `blacklist.providers` configuration.

Custom integrations still implement `BlacklistProvider.check(url, { signal }): Promise<{ matched: boolean; details?: string }>`. The PhishTank factory also accepts an optional trusted `fetch` replacement for offline tests. When invoking `provider.check` directly, supply a deadline signal yourself (for example `AbortSignal.timeout(5000)`); the checker normally owns the deadline.

### ML model: configuration required

**ML remains explicit opt-in.** Without configuration, inference returns `not_configured`,
with `null` probability/prediction. There are two independent supported paths:

1. **Published pretrained model:** the MIT-licensed `pirocheto/phishing-url-detection`
   Linear SVM, using its original ONNX graph and string preprocessing. Run
   `pnpm ml:download`, then `await loadPretrainedMlPhishingModule()` and pass the
   instance as pipeline option `mlModule`. It performs local asynchronous CPU
   inference, with no URL fetch or hosted API call. Dispose it at shutdown.
   See [provenance, license, usage, evaluation caveats, and offline tests](../../../models/phishing-url/README.md).
   Model weights are provisioned explicitly, not committed or downloaded at runtime.
   Its training date is unknown (`trainedAt: null`).
2. **Existing logistic artifact:** use `createMlPhishingDetector(artifact)`,
   `new MlPhishingModule(artifact)`, or pipeline option `mlModel`. This remains
   synchronous and uses the unchanged version-1 feature contract below. Supply
   your own trained/evaluated model; do not reuse unrelated model weights.

`mlModel` and `mlModule` are mutually exclusive. Library defaults and assessment
policy are unchanged. The standard HTTP entry point explicitly selects `mlModule`.
No production accuracy guarantee is made.

For the existing logistic path, load a trusted JSON artifact:

```ts
import { readFile } from 'node:fs/promises';
import { createMlPhishingDetector } from './modules/threat-detection/index.js';

// Set this environment variable to the path of your own evaluated model artifact.
const modelPath = process.env.PHISHING_URL_MODEL_PATH;
const detectMl = createMlPhishingDetector(
  modelPath ? JSON.parse(await readFile(modelPath, 'utf8')) : undefined,
);
const result = detectMl('https://example.com');
```

The artifact shape is the exported `LogisticUrlModel`:

| Field | Required value |
| --- | --- |
| `format` | `"xerxes-url-logistic-v1"` |
| `id` | Nonempty model identifier |
| `trainedAt` | Valid date string |
| `featureNames` | Exact ordered array exported as `URL_FEATURE_NAMES` |
| `means`, `scales` | Training-set standardization arrays; finite means and strictly positive finite scales |
| `weights` | Finite logistic coefficients in the same feature order |
| `intercept` | Finite intercept |
| `threshold` | Decision threshold strictly between 0 and 1, selected using evaluation data |

Each numeric array has 18 elements. For a model trained without standardization, use means of 0 and scales of 1. The model computes `sigmoid(intercept + sum(weights[i] * (features[i] - means[i]) / scales[i]))`. Output includes model ID, training date, estimated phishing probability, threshold, and `phishing | not_phishing` prediction. These labels are model predictions, not security verdicts; a probability is not necessarily calibrated. Validation checks artifact compatibility/numerics, not whether its training history is truthful or its model is effective.

Use `extractUrlFeatures()` to produce training data, so preprocessing matches inference exactly. A training library such as Python's **scikit-learn** (`StandardScaler` + `LogisticRegression`) can export the corresponding arrays; Python/scikit-learn are not server dependencies. Split by registrable domain and time where possible to reduce data leakage, assess precision/recall and false positives on a realistic benign population, then version and monitor the deployed model. No hand-written heuristic weights are presented as learned ML.

The version-1 feature order and definitions:

1. `urlLength`: serialized URL length, including fragment and user information if present.
2. `hostnameLength`: lowercase ASCII hostname length, excluding IPv6 brackets/trailing dot.
3. `pathLength`: serialized pathname length.
4. `queryLength`: serialized search length, including `?` when present.
5. `digitRatio`: ASCII digit count divided by serialized URL length.
6. `hostnameDigitRatio`: ASCII digit count divided by normalized hostname length.
7. `hostnameEntropy`: Shannon entropy of normalized hostname characters, in bits.
8. `dotCount`: dots in normalized hostname.
9. `hyphenCount`: hyphens in normalized hostname.
10. `subdomainCount`: labels before the registrable domain, using private suffixes.
11. `queryParameterCount`: parsed query entries, including duplicate keys.
12. `percentEncodedCount`: `%HH` occurrences in serialized URL.
13. `hasIpHost`: 0/1, including IPv6 and URL-parser-normalized numeric IPv4.
14. `hasCredentials`: 0/1 for embedded username/password.
15. `usesHttps`: 0/1.
16. `hasPunycode`: 0/1 for an `xn--` hostname label.
17. `hasNonDefaultPort`: 0/1 (explicit standard ports normalize away).
18. `suspiciousWordCount`: case-insensitive occurrences of `login`, `signin`, `verify`, `verification`, `password`, `secure`, `account`, `update`, `wallet`, or `recover` in the serialized URL.

## Validation and operational limits

All analyzers share a strict HTTP/HTTPS parser with an 8192-character input limit. Explicit `http://` or `https://` syntax and a nonempty authority are required; raw whitespace, control characters, backslashes, malformed DNS labels, labels over 63 characters, and hostnames over 253 characters (excluding a trailing root dot) are rejected. Valid IP literals, IDNA hostnames, and single-label hosts are supported. Input validation is deliberately stricter than WHATWG URL's repair behavior. Offline analyzers can report credentials/IPs without contacting them. Invalid inputs/configuration throw (or reject for the blacklist checker); redirect detection instead returns explicit error/blocked results. Returned URL values can contain sensitive query data or user information: redact before logging or exposing them.

Tests use injected transports/providers, synthetic logistic coefficients, and optional
offline inference against the explicitly provisioned pretrained artifact. They do not
contact suspicious sites, download models, or establish model accuracy.

From `server/`:

```sh
pnpm exec tsx --test test/threat-detection.test.ts test/http-redirect.test.ts test/blacklist.test.ts
pnpm typecheck
pnpm test
pnpm build
```
