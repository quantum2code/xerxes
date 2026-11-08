# Basic URL analysis

Offline inspection of URL structure, not a phishing verdict. Uses WHATWG `URL`, Node IP/IDNA helpers, and `tldts`. No DNS lookups, HTTP requests, blacklist queries, or brand comparisons occur here.

## Public API

```ts
import {
  BasicUrlAnalysisModule,
  analyzeBasicUrl,
} from './modules/threat-detection/basic-url-analysis/index.js';

const module = new BasicUrlAnalysisModule();
const result = module.analyze('http://2130706433/login');
// result.status: 'completed'
// result.evidence: URL_STRUCTURE and AUTH_KEYWORD observations, without severity.
// result.details.hostname: '127.0.0.1'
// result.details is the raw analyzeBasicUrl('http://2130706433/login') result.
```

`BasicUrlAnalysisModule` extends `ThreatDetectionModule<string, ModuleResult<BasicUrlAnalysis>>` and is synchronous. Instances hold no per-call mutable state and can be reused. `name` is `basicUrlAnalysis`, matching the DAG task. The [assessment module](../assessment/README.md), not this detector, assigns threat severity and generates the report.

## Input validation

Invalid inputs throw. The shared parser requires:

- A nonempty string up to 8192 characters.
- Explicit `http://` or `https://` and a nonempty authority. Parser-repaired forms such as `https:example.com` and `https:///example.com` are rejected.
- No raw whitespace, control characters, or backslashes. Percent-encoded whitespace in paths/queries remains supported.
- Valid normalized DNS host labels of 1–63 ASCII characters, with letters/digits and interior hyphens, and a maximum hostname length of 253 excluding the trailing root dot. Empty labels, underscores, and leading/trailing hyphens are rejected by this DNS-host policy, even though WHATWG URL accepts some of them.
- Alternatively, a valid URL-parser-normalized IP address. IPv6 must use brackets in URL syntax.

Internationalized domains are normalized through WHATWG IDNA. A single trailing root dot is supported. Single-label and local names are valid inputs and receive structural observations. No claim is made that a domain exists, resolves publicly, or has a valid certificate. HTTP/HTTPS parser policy is shared across all Engine 1 modules.

## Output and privacy

`ModuleResult<BasicUrlAnalysis>` exposes `module`, execution `status`, typed `evidence`, raw `details`, and `issues`. Each evidence item identifies `module`, `hostname`, and `target: 'submitted'`. It uses either `URL_STRUCTURE` (signal, location, value, optional threshold) or `AUTH_KEYWORD` (location, matched terms).

Raw `BasicUrlAnalysis`, available under `details` or directly from `analyzeBasicUrl()`, contains:

- `normalizedUrl`: full serialized URL, **including credentials if supplied**.
- `displayUrl`: serialized URL with username/password removed. **Query, path, and fragment may still contain secrets**; this field is not an unrestricted safe-to-log URL.
- `hostname`, `unicodeHostname`, `registrableDomain`, `publicSuffix`, `subdomain`.
- `features`: the fixed version-1 numeric lexical feature vector used by ML.
- `signals`: structural observations with `code`, `location`, `description`, and `evidence`; no severity, verdict, or risk score.

Missing registrable-domain data is represented as `null`. IP and single-label hosts may lack it. Private suffixes are included: `tenant.github.io` is the registrable domain for its tenant rather than `github.io`.

Evidence excludes usernames, passwords, full URLs, and query values. Still avoid logging the entire module result: raw diagnostics may contain credentials or sensitive URL components. Direct inspection can analyze credential-bearing URLs; the production DAG rejects them at validation before invoking any detector/provider.

## Structural observations

| Raw signal | Condition |
| --- | --- |
| `http` | Scheme is HTTP |
| `credentials` | Username/password present |
| `unusual_ip_notation` | IPv4 normalizes from a noncanonical spelling, e.g. decimal, hexadecimal, octal, shortened address, or percent-encoded digits |
| `ip_host` | Host normalizes to IPv4/IPv6 |
| `punycode` | Host has an `xn--` label; internationalization is not itself malicious |
| `non_default_port` | Port is nonstandard for the scheme |
| `long_url` | Serialized URL length > 200 |
| `many_subdomains` | At least 3 labels before the registrable domain |
| `many_hyphens` | At least 3 hostname hyphens |
| `encoded_characters` | At least 5 `%HH` occurrences in the serialized URL |
| `local_hostname` | Single-label host, or `localhost`, `local`, `internal`, or `home.arpa` suffix |
| `sensitive_keywords` | Authentication/account-related term in a hostname, path, query, or fragment |

Keyword detection is case-insensitive and substring-based. It reports each component independently and decodes percent encodings once when the component decodes successfully. Malformed escaping falls back to the serialized component; recursive decoding and browser/application-specific routing are intentionally not inferred. Terms such as `login` and `secure` are common on legitimate sites and do not by themselves establish impersonation or phishing.

Component-specific keyword evidence does **not** change ML feature definitions: version-1 `suspiciousWordCount` still counts the existing regular expression across the serialized URL without decoding, including user information if present.

## DAG integration

Validation returns the original submitted spelling and its normalized form. The basic handler consumes the original validated spelling, while other handlers use the normalized URL. Otherwise `http://2130706433/` would reach this module as `http://127.0.0.1/`, losing the unusual-notation observation. The final assessment depends on all five detector results and applies rules to their evidence.

## Tests

From `server/`:

```sh
pnpm exec tsx --test test/basic-url-analysis.test.ts test/threat-assessment.test.ts test/threat-detection-modules.test.ts test/threat-detection-pipeline.test.ts
pnpm typecheck
```

Tests cover parsing, IDNA/IPv6, local names, unusual IPv4 forms, evidence/privacy, keywords, thresholds, ML-feature compatibility, raw-details compatibility, and preservation of original spelling through the DAG. These deterministic tests establish implementation behavior, not phishing-detection accuracy.
