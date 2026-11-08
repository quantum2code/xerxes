# Module 4: Web Security Scanner

An independent TypeScript/Node.js application-security scanner. It does not classify phishing, consult reputation databases, validate certificate lifecycles, or compute unified risk. Normal HTTPS certificate verification is retained solely to secure outbound requests.

Module 1 is now integrated as an additional independent `urlAnalysis` root in the application DAG; see [URL Analyzer](url-analysis.md). It shares the extracted IP/redaction helpers, while Module 4 retains its authorization, stricter URL policy, checks and transport. The aggregation task also waits for URL analysis. Module 4 does not trust its report as a fetch target or grant.

## Installation

From `server/`, use Node.js >=22 and pnpm:

```sh
pnpm install
pnpm typecheck
pnpm test
pnpm build
pnpm start
```

Runtime dependencies: Express, `ipaddr.js` (special-purpose address classification), `parse5` (non-executing HTML parsing), and `semver` (advisory version ranges). No external reputation/advisory service is required. ZAP is optional. The malformed original multi-document pnpm lockfile was regenerated during installation.

## Architecture

```text
src/modules/web-security/
  types.ts, config.ts, scanner.ts, index.ts
  checks/         Registerable, non-networked response checks
  network/        URL/DNS policy, pinned transport, isolated ZAP gateway
  integrations/   Docker lifecycle and ZAP API adapter
  reporting/      Redaction, normalization, classification
src/pipelines/security-pipeline.ts
```

Checks inspect bounded `Page` snapshots; they cannot initiate network requests. `WebSecurityScanner` owns traversal, authorization, budgets, deduplication, status and normalization. Production requests use `createTransport`, not unrestricted `fetch`. Injectable transports/checks/Docker runners are trusted **code-level testing interfaces**, never request-configurable options.

```text
certificateValidation --------------------+
threatIntelligence -> threatAnalysis ------+-> securityAssessment
webSecurityScan --------------------------+
```

Existing mock modules remain mocks, including the mock threat score. `securityAssessment.findings: string[]` is retained; `securityAssessment.webSecurity` adds scanner status, counts, structured findings, and limitations. Module 6 must consume status/coverage as well as findings: **an empty array is not a safe verdict**. The DAG engine is unchanged. The old four-task `pipelines/mock-pipeline.ts` factory remains available for legacy consumers/tests.

## Authorization and scope

Both modes require authorization by default. Provision grants only after your operator verifies permission to assess the target. A grant is an unguessable bearer capability for **one exact origin** and explicitly listed modes, expiring at a fixed timestamp. The software enforces a grant; it cannot establish legal ownership by itself.

Set `WEB_SECURITY_GRANTS` to a JSON array, supplied by a secret manager or trusted process environment:

```json
[
  {
    "token": "REPLACE_WITH_A_RANDOM_SECRET_OF_AT_LEAST_32_CHARACTERS",
    "origin": "https://your-authorized-site.example",
    "modes": ["passive"],
    "expiresAt": "REPLACE_WITH_A_NEAR_FUTURE_ISO_TIMESTAMP"
  }
]
```

Generate a secret with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. Use short expiry periods and rotate/revoke grants through service configuration. Add `"active"` to `modes` only after explicit active-testing authorization. A submitted `authorized: true` flag, caller-supplied scope, or forged token cannot authorize a scan. Revocation takes effect when the service configuration is reloaded/restarted; scans are deadline-limited by the original grant expiry. Grants currently cover whole origins, not path-restricted scopes: do not issue a grant if permission is narrower.

Only HTTP(S), default/explicit ports 80 and 443, and credential-free URLs are accepted. Fragments, local discovery names, and ambiguous backslash/control-character inputs are rejected. Crawling and redirects never cross the original origin (including HTTP-to-HTTPS redirects); submit the final authorized origin yourself.

`WEB_SECURITY_REQUIRE_PASSIVE_AUTH=false` permits public-target passive scans without a grant as an explicit deployment choice. It **never** relaxes active authorization or network restrictions. Passive GET requests can still cause application side effects; the operator remains responsible for permission and appropriate exposure controls.

## Configuration

| Environment variable | Default | Limit/meaning |
|---|---:|---|
| `WEB_SECURITY_GRANTS` | `[]` | Server-provisioned grants; never log this value |
| `WEB_SECURITY_REQUIRE_PASSIVE_AUTH` | `true` | Only literal `false` opts out for passive mode |
| `WEB_SECURITY_REQUEST_TIMEOUT_MS` | 5000 | 1–30000, including DNS and response reads |
| `WEB_SECURITY_SCAN_TIMEOUT_MS` | 30000 | 1–300000, total native + ZAP deadline |
| `WEB_SECURITY_MAX_RESPONSE_BYTES` | 1048576 | 1–5242880, per response; encoded responses rejected |
| `WEB_SECURITY_MAX_REQUESTS` | 10 | 1–100, native plus forwarded active requests |
| `WEB_SECURITY_MAX_REDIRECTS` | 3 | 1–10 per native redirect chain; active redirects also consume request budget |
| `WEB_SECURITY_REQUEST_INTERVAL_MS` | 250 | 1–10000, minimum gap per scan |
| `WEB_SECURITY_MAX_CONCURRENT_SCANS` | 4 | 1–32 per scanner instance; excess scans return blocked |
| `WEB_SECURITY_ZAP_ENABLED` | `false` | Only literal `true` enables Docker backend |
| `WEB_SECURITY_ZAP_IMAGE` | `ghcr.io/zaproxy/zaproxy:stable` | Preinstalled trusted image, preferably digest-pinned |
| `WEB_SECURITY_GATEWAY_IMAGE` | `xerxes-web-security-gateway:local` | Locally built trusted gateway image |
| `WEB_SECURITY_ZAP_TIMEOUT_MS` | 120000 | 1–300000, also bounded by total scan/grant deadlines |

Native crawl depth is fixed at 1, with sequential requests per scan. Only same-origin anchor links and script sources are followed. Discovered query links and obvious destructive/logout paths are skipped. No hidden-file enumeration, forms, authentication, cookie replay, or scripted crawling occurs. HTML structure parsing is capped at the first 256 KiB and 10,000 tag starts per response, with 500 findings per report. Text signatures still inspect the bounded response body. These are safety/coverage limits, not a claim that GET is universally side-effect-free.

## API examples

Use your authorized target and a provisioned grant; `.example` values below are documentation placeholders, not scan targets. Protect the Xerxes API with authenticated TLS ingress, ingress rate limits, request-log redaction, and tenant access controls. The grant is supplied in the JSON body; do not enable body logging.

### Passive (default, no ZAP required)

```sh
curl -X POST http://localhost:3000/api/web-security/scan \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://your-authorized-site.example/","authorizationToken":"YOUR_PROVISIONED_SECRET"}'
```

`POST /api/analyze` accepts the same input and returns the DAG task outputs keyed by task name, including `webSecurityScan` and `securityAssessment`. `GET /health` remains unchanged. The standalone route returns HTTP 403 for blocked scans, 502 for failed scans, and 200 for completed/partial scans; callers must inspect JSON status. The pipeline route returns all structured results with HTTP 200 even when scanner status is blocked/failed. Malformed JSON is 400; bodies over 16 KB are 413.

Example completed native result for a fixture with one missing hardening header (coverage text shortened):

```json
{
  "schemaVersion": "1.0",
  "targetUrl": "https://your-authorized-site.example/",
  "mode": "passive",
  "status": "completed",
  "durationMs": 120,
  "checksExecuted": ["security-headers", "cookies", "cors", "mixed-content", "information-disclosure", "directory-listing", "sensitive-exposure", "insecure-forms", "dependencies"],
  "checksSkipped": [{"checkId":"zap","reason":"Optional backend disabled"}],
  "counts": {"informational":0,"low":1,"medium":0,"high":0,"critical":0},
  "coverageLimitations": ["Only bounded same-origin HTTP responses are assessed; no finding does not imply a secure website."],
  "findings": [{
    "id":"d7ecaa39-5f2c-4eae-9170-688bb5a18bb7",
    "checkId":"security-headers",
    "title":"MIME sniffing protection not observed",
    "description":"This is a defense-in-depth configuration observation, not evidence of a successful exploit.",
    "severity":"low",
    "confidence":"high",
    "affectedUrl":"https://your-authorized-site.example/",
    "evidence":[{"location":"HTTP response","observation":"X-Content-Type-Options is absent or not nosniff"}],
    "cwe":[],"owasp":["A05:2021"],"cves":[],
    "remediation":"Send X-Content-Type-Options: nosniff with correct content types.",
    "source":"native",
    "detectedAt":"2026-11-07T12:00:00.000Z"
  }],
  "backend":{"native":"available","zap":"disabled"}
}
```

Complete machine-readable contract: [`web-security-scan.schema.json`](./web-security-scan.schema.json). Findings have per-detection UUIDs, not persistent cross-scan identifiers. Confidence describes confidence in the observation, not exploitability. OWASP references use the explicitly versioned **2021** taxonomy. No CVSS or final risk score is inferred. ZAP risk levels map to informational/low/medium/high; the schema supports critical but currently no built-in rule emits it.

Statuses: `completed` means configured work finished within its documented scope; `partial` retains useful findings but work/checks/backend coverage is incomplete; `blocked` means input, permission, network policy, or capacity disallowed assessment; `failed` means no useful native response could be assessed. Optional backend state is separate. A configured but unavailable ZAP backend produces a partial result, not a crash or a safe verdict. `checksExecuted` means a check was invoked, including applicability evaluation; it does not assert every resource/application feature was covered. A check can appear in both lists if it failed for one response but ran for another.

## ZAP Docker setup

Requires a running **Linux** Docker daemon and trusted preinstalled ZAP image with `network`, `exim`, passive rules, and the selected active rules. From `server/`:

```sh
docker pull ghcr.io/zaproxy/zaproxy:stable
docker build -f docker/web-security-gateway.Dockerfile -t xerxes-web-security-gateway:local .
```

Pin tested image digests in production. The backend never pulls images automatically. Set `WEB_SECURITY_ZAP_ENABLED=true` and, for practical ZAP startup/assessment time, `WEB_SECURITY_SCAN_TIMEOUT_MS=180000` and `WEB_SECURITY_ZAP_TIMEOUT_MS=180000`. Increase request budget deliberately (maximum 100); the default of 10 will often produce partial active coverage. Rebuild the gateway image after scanner changes. Missing Docker, unsupported daemon OS, missing images, API/add-on errors and isolation failures are represented explicitly.

Each scan starts a fresh resource-limited, read-only, capability-free ZAP container with **`--network none`**. Its API listens only on loopback and is invoked via `docker exec` with a fresh API key. No host port or Docker socket is mounted in a worker.

* **Passive:** ZAP imports a redacted HAR of responses already fetched by the safe native transport. It makes no target requests and has no gateway at all. This mode works for HTTP and HTTPS without running a browser.
* **Active:** a separate Node gateway container has an outbound bridge connection and a single Unix listener on an ephemeral Docker volume. A short, fixed Python standard-library relay inside the existing ZAP image joins ZAP's loopback upstream proxy to that socket; it is transport plumbing, not a Python analysis service. ZAP still has no network interface capable of external access. The gateway enforces exact origin, grant deadline, public DNS/connection addresses, request/response limits, allowed methods, serialization, rate limits and the remaining request budget. CONNECT and WebSocket upgrades are denied. No arbitrary Host, Authorization or Cookie supplied by ZAP is forwarded.

For HTTPS active scans, ZAP operates on an HTTP representation of the same target; the gateway translates to the authorized HTTPS origin and performs normal certificate validation. Same-origin redirect Locations are translated back for ZAP. Off-origin Locations remain visible as evidence for open-redirect rules, but the gateway never follows them and rejects out-of-scope follow-up requests. Only active alert IDs are collected, excluding misleading passive alerts caused by the synthetic HTTP representation. This provides a bounded HTTP request assessment, **not** browser/secure-context equivalence. No real HTTPS downgrade occurs on the upstream connection.

### Authorized active scan

Provision a grant explicitly containing `active` before using:

```sh
curl -X POST http://localhost:3000/api/web-security/scan \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://your-authorized-site.example/search?q=example","mode":"active","authorizationToken":"YOUR_ACTIVE_GRANT_SECRET"}'
```

Only reflected XSS (40012), SQL injection (40018) and open redirect (10028) rules are enabled at LOW attack strength, MEDIUM alert threshold, and one thread. The submitted endpoint is scanned non-recursively. There is no OAST, login, session handling, file execution, browser, or unbounded spider. Missing rules fail closed. Gateway denials, budget exhaustion and upstream failures prevent a completed active claim. Findings obtained before a normal budget-limited completion are retained; a backend interruption/API error currently discards backend findings rather than returning unverifiable partial data. Native findings are retained.

Containers/volumes are removed in `finally`, including cancellation. A daemon failure can prevent cleanup: monitor Docker for orphaned `xerxes-zap-*`, `xerxes-gateway-*`, `xerxes-policy-*` resources and remove **only verified owned resources**. The gateway expires its own policy even if its controller dies. Deploy the Docker controller on a dedicated worker: Docker daemon access is highly privileged. This is not a hardened multi-tenant Docker control plane or protection against kernel/container-runtime compromise.

## Native checks and limitations

| Check | Detection and important caveats |
|---|---|
| Security headers | Enforcing CSP/script restrictions, HTTPS HSTS positive max-age, nosniff, Referrer-Policy, CSP frame-ancestors/X-Frame-Options. Missing protections are low-severity hardening observations, not exploit proofs. This is not a complete CSP grammar/semantic validator. |
| Cookies | Secure, HttpOnly, valid SameSite, None-without-Secure. Cookie values/names omitted. Cookie purpose is unknown; non-session cookies may intentionally permit scripts. Browser defaults can mitigate absence. |
| CORS | Wildcard public reads (informational), invalid wildcard+credentials (low, browsers reject it), credentialed null origins (medium confidence). No Origin mutation/preflight or sensitive-data verification; reflection bugs can be missed. |
| Mixed content | Static HTTP resource references, including base URLs and srcset, distinguished from navigation links. Browsers/CSP may block or upgrade content. CSS/JS-generated resources are not assessed. |
| Disclosure | Version/technology headers, recognizable error/stack signatures, development comments. Documentation/code samples can match; no vulnerable server version is inferred. |
| Directory indexes | Multiple directory heading/navigation indicators required. Custom listings may be missed; intended public indexes may match. |
| Sensitive responses | Private-key delimiters, AWS key identifiers, selected environment credential assignments in already returned content. No hidden `.env`/backup probes, validity checks, or arbitrary secret inventory; sample keys may match. |
| Forms | HTTP actions, submit-control action/method overrides, and GET forms containing a named enabled password input. No submission or browser behavior verification; disabled-fieldset/script transformations can cause differences. |
| Dependencies | Fetched JS/text jQuery version banner, not filename guessing. Snapshot: GHSA-gxr4-xjj5-5px2 / CVE-2020-11022, npm range >=1.12.0 <3.5.0, confirmed against GitHub advisory on 2026-11-07. Supported remediation >=3.5.0. Banners can be stale/forged; vulnerable API use is not established. Other libraries, hashed/versionless bundles and patched vendor forks are not reliably assessed. No automatic advisory updates. |

Reports omit cookie values, stack contents, secret matches and arbitrary ZAP attack/evidence bodies. URL query values are always redacted; long/credential-like path segments and common credential/JWT/key patterns are masked. This necessarily reduces exact reproduction fidelity: retain the original submitted URL in an access-controlled caller system and re-run the referenced check under authorization. Redaction is defense-in-depth, **not a general DLP guarantee for every possible secret representation**. Raw responses necessarily exist transiently in scanner memory and active ZAP/gateway memory; ZAP storage is ephemeral tmpfs. Protect process memory, Docker access and host diagnostics. Avoid credential-bearing target URLs altogether.

DNS answers are checked for prohibited addresses on **every request**, including redirects. All answers must be public; a chosen address is pinned to the actual connection, original Host/SNI retained, and the peer address checked again. Loopback, private, link-local, multicast, reserved, carrier-grade NAT, mapped/transition IPv6 and known metadata/platform addresses are blocked. No environment proxy, pooled connection or fallback resolver can bypass this transport. Local integration fixtures are test-only; production has no private-network bypass.

Public classification cannot detect a globally numbered address privately routed by a misconfigured host network, or every NAT64 prefix. Apply independent host/worker egress firewall policy denying internal/platform networks, including your organization's globally numbered internal ranges; do not deploy in a network where public-looking destinations can transparently route to sensitive systems. Built-in active isolation prevents ZAP from directly reaching host/internal services even if ZAP ignores proxy settings. Authorization and all native address checks remain mandatory.

## Tests and extending checks

```sh
pnpm exec tsx --test test/web-security-*.test.ts
pnpm test
pnpm typecheck
pnpm build
```

Unit/API/DAG tests use response fixtures and injected transports, never public target scans. They cover all passive checks, normalization, severity/confidence, grant/scope enforcement, DNS rebinding, actual peer mismatch, redirects, response sizes/encodings, timeouts, partial failures, capacity, concurrency, gateway restrictions and mocked Docker/ZAP lifecycle/errors. The legacy certificate regression expectation was corrected to match its existing `false` fixture; certificate functionality was not changed.

Live tests are skipped by default. Enable `XERXES_TEST_ZAP_DOCKER=1` to run offline HAR integration against real Docker ZAP. Enable `XERXES_TEST_ZAP_ACTIVE_LAB=1` for the purpose-built reflected-XSS fixture on an **internal-only Docker bridge**, with no published ports or Internet route. Its synthetic address exists only inside that isolated lab; a test-only Docker adapter places the gateway on that bridge. Neither test weakens production SSRF policy. Both require the images above; the active lab requires its fixed subnet not to conflict with existing Docker networks. Never substitute a third-party production target.

To add a check, implement `Check` with a unique `id` and synchronous `run(page): FindingInput[]`, register it in `checks/index.ts` (or pass a trusted custom list to the scanner), and add fixture tests for positive/negative evidence and false positives. Return structural/minimal evidence, never raw cookies, input values or response excerpts containing secrets. Use defensible CWE/OWASP references only; do not infer CVEs or CVSS. Add new network behavior to the bounded orchestrator/transport, **not inside checks**. Update schema/documentation when changing contracts.

Deployment verification note: the implementation environment had Docker installed but its daemon was unavailable. Mocked ZAP/gateway tests and the TypeScript build can be verified there; real Docker integration must be run on a prepared Linux-Docker worker before treating optional ZAP coverage as deployment-validated.

### Recorded implementation verification

On Node.js 24.14.0 with pnpm 10.7.1:

* `pnpm test`: 100 tests; 98 passed, 2 opt-in live Docker tests skipped, 0 failures.
* `pnpm typecheck` and `pnpm build`: passed.
* `pnpm audit --prod`: no known vulnerabilities reported by the registry at verification time (not a security guarantee).
* `git diff --check`: passed.

No active assessment of a third-party target was performed. The real Docker image build and live ZAP tests remain unverified on this host because its Docker Linux daemon was not running.
