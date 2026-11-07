# Module 1: URL Analyzer — DNS, HTTP, URL parsing

Module 1 extracts URL features, DNS records, and HTTP metadata. It does **not** classify phishing, assign risk, look up reputation, grade security headers, execute JavaScript, test vulnerabilities, or analyze certificates. Features and observed failures are data for downstream modules, not proof of maliciousness or legitimacy.

## Installation and library choices

From `server/`, using Node.js >=22:

```sh
pnpm install
pnpm typecheck
pnpm test
pnpm build
pnpm start
```

New runtime dependencies:

* `tldts ^7.4.19`: maintained Public Suffix List parsing, including private suffixes (`allowPrivateDomains: true`). No homemade suffix matching.
* `undici ^7.30.2`: supported 7.x HTTP client/connector APIs compatible with the repository's Node >=22 range. Undici 8 requires Node >=22.19; the server's engine requirement was not unnecessarily raised.
* `zod ^4.6.7`: validates request/configuration/DNS response shapes without returning raw validation messages containing input.

Existing `ipaddr.js ^2.5.0` is reused for IP classification. Built-in WHATWG `URL`, `node:url` IDN conversions, `node:dns/promises.Resolver`, Node TLS verification, and `performance.now()` handle standards-defined behavior and monotonic durations. There are no additional services, reputation APIs, Redis, databases, browsers, or custom DNS/HTTP/IP protocol parsers.

## Structure

```text
src/modules/url-analysis/
  types.ts, config.ts, errors.ts, analyzer.ts, index.ts
  url/parser.ts       WHATWG parsing, PSL, structured URL representation
  url/normalize.ts    Secret-safe report URLs (not network targets)
  url/features.ts     Small deterministic lexical calculations
  dns/resolver.ts     Independent cancellable record queries and fresh connection DNS
  dns/records.ts      Record validation, limits, classification, TXT privacy
  http/transport.ts   Per-request Undici dispatcher and immediate body disposal
  http/client.ts      HEAD/fallback, metadata, manual redirect orchestration
  http/redirects.ts   PSL-aware redirect observations
  security/          Port/hostname/address policy and pinned socket connector
src/shared/network/
  policy.ts           Shared Module 1/4 IP classification and public-address policy
  limits.ts           Bounded, abortable concurrency semaphore
src/shared/security/redaction.ts
```

Module 4's existing `network/policy.ts` and `reporting/normalize.ts` re-export the extracted helpers, preserving existing imports, error identity and behavior. Its stricter URL policy, authorization, scanner, checks and ZAP backend remain separate. Neither module trusts another module's prior DNS validation as permission to connect.

`UrlAnalyzer` is reusable independently:

```ts
import { UrlAnalyzer, loadUrlAnalysisConfig } from './src/modules/url-analysis/index.js';

const analyzer = new UrlAnalyzer(loadUrlAnalysisConfig()); // Reuse one instance, not one per request.
const result = await analyzer.analyze({ url: authorizedTarget }, abortController.signal);
```

The optional query, transport and connector-builder injection points are trusted code-level testing adapters. They are not exposed through request JSON and must never be populated from client configuration.

## API and output contract

### Standalone metadata analysis

```sh
curl -X POST http://localhost:3000/api/url-analysis \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://your-authorized-site.example/login?account=example#section"}'
```

Use a site you are authorized to assess; the `.example` target is a documentation placeholder. Module 1 issues low-impact HEAD/GET requests and does not use Module 4's active-scan grants. Deploy the service behind authenticated, TLS-protected ingress with rate limits and tenant controls. Never enable body/query logging that would record submitted URLs or Module 4 grant tokens.

HTTP status: 200 for completed/partial results, 400 for invalid URL input, 403 for blocked targets/capacity. Other uncaught application errors use the existing sanitized Express error handler. The existing 16 KB JSON-body limit remains in effect; Module 1 URLs are limited to 4096 UTF-16 code units. Body arrays, missing `url` and non-string URLs are rejected. Extra pipeline fields, such as Module 4's authorization token, are ignored and never copied into the report.

`POST /api/analyze` accepts the same JSON plus any other module inputs. It returns task outputs, including `urlAnalysis`, `webSecurityScan`, and the separate `securityAssessment`. Expected module failures remain structured results; the DAG does not abort independent modules merely because URL analysis reports a failed/blocked subsystem.

Illustrative selected fields from a successful **fixture**, not a recorded public website assessment (the full result also contains query statuses, features, limits and other required fields):

```json
{
  "module": "urlAnalysis",
  "schemaVersion": "1.0",
  "status": "completed",
  "input": "https://www.example.com/login?account=%5BREDACTED%5D",
  "durationMs": 142,
  "url": {
    "original": "https://www.example.com/login?account=%5BREDACTED%5D",
    "normalized": "https://www.example.com/login?account=%5BREDACTED%5D",
    "scheme": "https", "hostname": "www.example.com",
    "asciiHostname": "www.example.com", "unicodeHostname": "www.example.com",
    "port": 443, "explicitPort": false,
    "path": "/login", "queryParameterNames": ["account"], "queryParameterCount": 1,
    "hasFragment": true, "domain": "example.com", "publicSuffix": "com",
    "subdomain": "www", "domainLabels": ["www", "example", "com"],
    "isIpAddress": false, "ipVersion": null
  },
  "dns": {"status":"completed","a":[],"aaaa":[],"cname":[],"mx":[],"ns":[],"txt":[],"errors":[]},
  "http": {
    "status":"completed","statusCode":200,
    "finalUrl":"https://www.example.com/login?account=%5BREDACTED%5D",
    "method":"HEAD","redirects":[],"redirectCount":0,"requestCount":1,
    "responseTimeMs":120,"contentType":"text/html","contentLength":1024,
    "headers":{"content-type":"text/html","content-length":"1024"},"errors":[]
  },
  "errors":[]
}
```

Complete public contract: [`url-analysis.schema.json`](url-analysis.schema.json); TypeScript interfaces: [`types.ts`](../src/modules/url-analysis/types.ts). Automated tests validate real result objects against the JSON schema. No field is a final phishing verdict or aggregated score.

### Status/error semantics

* **Overall completed:** URL parsed; DNS completed or legitimately skipped for an IP literal; HTTP metadata completed.
* **Overall partial:** parsing/features succeeded but DNS/HTTP failed, timed out, was cancelled, or DNS reporting was truncated. Useful independent data is retained, even if both network subsystems fail.
* **Overall blocked:** static/network policy or analyzer capacity prevented access; parsing/features and any completed DNS information can still be present.
* **Overall failed:** invalid input could not be parsed safely; `url` and `features` are null and no network operation starts.

DNS has `completed`, `partial`, `failed`, `skipped`. Each of A/AAAA/CNAME/MX/NS/TXT has an explicit `queries` entry with status `completed`, `absent`, `failed`, or `skipped`, duration, truncation flag and optional structured error. Empty arrays alone do not describe success/absence/failure. `ENODATA` is `absent`, not a subsystem failure; its diagnostic may appear in `errors` while overall DNS remains completed. NXDOMAIN (`ENOTFOUND`) and temporary errors remain failures. Missing MX/NS/TXT does not produce a suspiciousness signal.

HTTP has `completed`, `failed`, `blocked`, `timed_out`, `cancelled`, `skipped`. Completion means headers received, **not** a complete page download or a healthy HTTP status: 404/500 responses can legitimately have completed metadata. Status/final URL/headers retain the last observed response on later failure. `method` describes the last attempted method; after failed GET fallback, retained metadata can describe the preceding HEAD response. `requestCount` counts attempts, including connection/DNS failures, not proof that HTTP bytes were sent. `responseTimeMs` covers the entire HTTP workflow including queuing, connection DNS, redirects and fallback. Durations are rounded monotonic milliseconds, not DNS TTLs or timestamps.

Errors have `stage`, stable `code`, safe `message`, `retryable`, and optional `recordType`. Native DNS, connection and TLS codes are allowlisted and retained (e.g. `ENOTFOUND`, `ESERVFAIL`, `ECONNRESET`, `CERT_HAS_EXPIRED`, `ERR_TLS_CERT_ALTNAME_INVALID`, `UND_ERR_CONNECT_TIMEOUT`). Raw error messages, stacks, certificates and submitted URLs are not copied into errors. `retryable` is descriptive; there are **no automatic retries** and no retry implementation in the current DAG runner. Permanent invalid/blocked destinations are not marked retryable; capacity is transient. Certificate connection errors are not phishing conclusions and do not replace Module 3.

## URL parsing, normalization and features

The private in-memory `target: URL` is WHATWG-normalized: IDNs become ASCII/Punycode, default ports normalize away, empty paths become `/`, path segments normalize, percent encoding/query data follow URL/URLSearchParams semantics, fragments are excluded from network requests. No scheme is silently added/reinterpreted. Explicit credentials (including empty user-info syntax), raw controls, whitespace and backslashes are rejected. Nonstandard ports are valid **parsing** inputs and produce features, but network access requires the configured allowlist. WHATWG-valid reserved port 0 is retained as parsing data but is never network-allowlisted.

`original` and `input` preserve submitted lexical formatting/casing and explicit default-port spelling where safe, while redacting query values and removing fragments. Opaque/credential-like paths are normalized and redacted when needed. `normalized` and `http.finalUrl` are **redacted reporting representations**, not the exact private connection URL. Never fetch a serialized report URL containing redaction placeholders. `path` is likewise redacted; `queryParameterNames` preserves duplicates and order; counts refer to actual parsed parameters, not redacted/reduced values. Fragment presence is a boolean only, including an empty `#`. IPv6 `hostname` is unbracketed; serialized URL forms retain brackets. Network defaults are reported as effective numeric ports, with `explicitPort` retained separately.

`tldts` supplies registrable domain, public suffix and subdomain using both ICANN and private suffix lists, including `co.uk` and hosted tenant suffixes such as `github.io`. Unknown suffixes return null domain/suffix/subdomain instead of claiming that a heuristic split is PSL-backed. IP literals also have null domain/suffix/subdomain and empty domain labels. ASCII and Unicode hostnames are both available; Unicode display must not be treated as an identity/security guarantee. DNS uses ASCII hostnames. Ambiguous IPv4 forms accepted by WHATWG (hexadecimal, octal, single-integer) are analyzed under their canonical IP identity and flagged `nonCanonicalIpv4`; unsafe canonical addresses remain blocked. This lexical flag never changes connection policy.

Features are calculated from the original valid submitted URL before report redaction unless noted:

* URL length: UTF-16 code units; hostname length: canonical unbracketed ASCII hostname; path length: normalized encoded network pathname.
* Parameter count and PSL-derived subdomain count; dots/hyphens/ASCII digits counted across the original URL.
* Special-character count: code units outside ASCII A–Z/a–z/0–9 (includes separators and non-ASCII characters).
* IP literal, Punycode in normalized domain labels, valid percent escapes, non-default effective port, noncanonical IPv4, repeated path slashes, repeated percent encoding and embedded HTTP(S) syntax.
* Whole-word `login`, `verify`, `account`, `secure`, `update` booleans after at most one `decodeURIComponent` pass and ASCII-word tokenization. Invalid percent encoding remains lexical data.
* Shannon entropy `H = -Σ p(c) log2 p(c)` over Unicode code points in the original URL, in **bits per character**. Empty/uniform strings return zero. Entropy is not an anomaly probability or score.

Features can reveal aggregate information such as input length/word presence despite value redaction. All returned strings remain untrusted display data; downstream UIs must render them as escaped text. This is not a general-purpose DLP or IDN homograph detector.

## DNS engine

`node:dns/promises.Resolver` resolves A and AAAA with `{ttl:true}`, CNAME, MX, NS and TXT independently. TTLs on A/AAAA are seconds and are reported exactly, including zero. TTLs unavailable through the chosen APIs for other record types are not invented. CNAME answers are canonical-name observations, not ownership validation or a separately followed connection instruction. MX priorities and exchange names are retained, including null-MX empty exchange values where returned by Node.

Each operation has its own resolver with one native attempt, cancellation and a deadline including concurrency-queue wait. Cancelling one record query cannot cancel another record's resolver. Node may use its normal DNS protocol/family behavior; the module does not implement DNS packets, DNSSEC validation, a custom resolver service, or operating-system hosts-file semantics. Query errors preserve successful answers. Record arrays and TXT reporting bytes are bounded; truncation is explicit and makes DNS partial.

TXT often contains verification capabilities. Reports retain record kind (SPF/DMARC/DKIM/verification/other) and byte length, but **always redact contents** into `[REDACTED TXT]`. This deliberately prevents raw TXT verification tokens from entering API logs/reports; consumers needing raw contents need a separate authorized/privacy-reviewed interface, not a client flag. TXT absence is informational. Query duration includes semaphore wait; TTL is unrelated to that duration.

Fresh independent A/AAAA queries are used before **each HTTP connection**; truncated reporting arrays are never trusted for access control. All returned addresses must be allowed, including addresses beyond the report limit. A single-family `ENODATA` is normal; temporary failures in either family fail closed, as does an inconsistent NXDOMAIN combined with a positive answer. The first approved address is pinned; no connection fallback/retry occurs. IPv4-only/IPv6-only domains work. Different DNS snapshots can show different public CDN addresses over time. Optional TTL caching is intentionally not implemented; there is no stale address cache to bypass checks.

## HTTP behavior and network safety

Each hop starts with HEAD. A single bounded GET fallback is used for 405/501 or a successful HEAD lacking **both** content type and content length. Other failures are not automatically retried. Low-level `undici.request` has no redirect interceptor; redirects are handled explicitly for 301, 302, 303, 307, 308. Each destination is reparsed and validated; DNS/connection checks are repeated for each connection, including fallback.

Valid redirect hops contain source URL, status, redacted target and PSL-domain crossing (null when a registrable-domain comparison is unavailable, e.g. IPs). Cross-domain redirects are observations, not maliciousness. `redirectCount` is the number of recorded valid-target redirects, including a final un-followed limit/blocked/loop hop; at most `maxRedirects` are followed. `followed` means target response metadata was obtained, not merely that a connection was considered. Unsupported/credential-bearing/malformed targets and missing Location produce structured errors; the preceding response remains available. HTTPS-to-HTTP redirects are recorded and followed only if the HTTP destination passes policy; no downgrade verdict is inferred.

Only content type **essence** (no arbitrary MIME parameters), safe content length, a parsed Date and allowlisted method names in Allow are returned as headers. Cookies, authorization, arbitrary headers, raw Location, server versions and security-header grading are excluded. Content-Length is reported, not trusted as proof of complete delivery. HEAD may report a large page size without downloading it. GET with a declared size above the cap fails; all bodies are closed immediately without draining, decompressing, parsing, saving or executing them. Unknown-length streams are not fully downloaded to determine their size. Undici applies a receive/parser cap and strict header size limit; transport buffers/packet overhead are not an exact process-memory quota.

The shared `ipaddr.js` policy rejects private, loopback, link-local, multicast, carrier-grade NAT, reserved/special-purpose ranges, mapped/transition IPv6 and known metadata/platform addresses (including Azure's globally numbered virtual platform address). Mapped IPv6 records expose their underlying IPv4 classification information but remain prohibited as destinations. Public classification is an address-policy observation, not a reachability or legitimacy guarantee.

DNS prevalidation is **not** the only safeguard. A per-request Undici dispatcher uses a connector built from Undici's standard connector with an approved-only lookup, explicit address family, no family autodetection, normal TLS verification and original-host SNI. The actual peer address is checked against the approved public address **before the socket is returned to Undici**, so no HTTP request bytes precede verification. TLS error checking remains enabled for domains and IP literals. Original HTTP Host is preserved by Undici. There is no global dispatcher, environment-proxy dispatcher, cookie jar, pooled cross-request socket or user-selected proxy/servername.

No general-purpose browser or scanner backend is launched. Limits, cancellation and `finally` disposal destroy request dispatchers/response streams. DNS uses per-operation cancellable resolvers. Public address classification cannot discover every custom NAT64 prefix, transparent routing policy or globally numbered private organizational route. Deploy with host/worker egress firewall protections appropriate to your network; do not expose this service in an environment routing public-looking destinations to sensitive internal systems. The service blocks known unsafe targets rather than providing an unsafe fallback or request-configurable internal-network bypass.

## Configuration and limits

All variables are trusted server configuration, not request parameters. Invalid configuration fails startup with the variable name, never its value.

| Variable | Default | Maximum/meaning |
|---|---:|---|
| `URL_ANALYSIS_TIMEOUT_MS` | 15000 | 60000; whole analysis |
| `URL_ANALYSIS_DNS_TIMEOUT_MS` | 2000 | 10000; per query, including queue wait |
| `URL_ANALYSIS_REQUEST_TIMEOUT_MS` | 4000 | 15000; per HEAD/GET including DNS and queue wait |
| `URL_ANALYSIS_MAX_CONCURRENT` | 4 | 32; whole analyses per instance, excess blocked |
| `URL_ANALYSIS_DNS_CONCURRENCY` | 4 | 32; shared by metadata and connection DNS |
| `URL_ANALYSIS_HTTP_CONCURRENCY` | 4 | 32; live metadata requests per instance |
| `URL_ANALYSIS_MAX_DNS_RECORDS` | 32 | 128; per report record type |
| `URL_ANALYSIS_MAX_DNS_TEXT_BYTES` | 4096 | 16384; reported TXT aggregate per analysis |
| `URL_ANALYSIS_MAX_REDIRECTS` | 5 | 0–10 followed redirects |
| `URL_ANALYSIS_MAX_HTTP_REQUESTS` | 12 | 24; attempts across HEAD/fallback and redirects |
| `URL_ANALYSIS_MAX_RESPONSE_BYTES` | 16384 | 65536; receive/parser cap and declared GET size cap |
| `URL_ANALYSIS_MAX_HEADER_BYTES` | 16384 | 32768; per response |
| `URL_ANALYSIS_ALLOWED_PORTS` | `80,443` | 1–32 explicitly allowed ports, 1–65535 |
| `URL_ANALYSIS_USER_AGENT` | `Xerxes-UrlAnalysis/1.0` | 1–128 printable ASCII characters, no controls |

Other positive numeric minimums are 1. URL length is fixed at 4096. Semaphores have bounded 128-waiter queues and remove cancelled waiters; active slots remain reserved until cancellable native operations finish. Limits are instance-local, not distributed tenant quotas. Ingress rate limits remain necessary. HTTP/DNS execute concurrently for independent partial coverage, but share their respective global-per-analyzer limits. A short total/request deadline can prevent queued DNS queries from starting; that is reported, not silently treated as absent records.

## DAG consumption and compatibility

```text
urlAnalysis ------------------------------+
certificateValidation --------------------+
threatIntelligence -> threatAnalysis ------+-> securityAssessment
webSecurityScan --------------------------+
```

The application constructs `buildSecurityPipeline(scanner, urlAnalyzer)`. The optional second argument preserves existing one-argument factory consumers and deterministic Module 4 tests; one-argument calls intentionally retain the old five-task graph. The application always supplies the real analyzer. The four-task legacy mock factory is unchanged.

`securityAssessment` retains its existing `findings` and `webSecurity` fields and adds `urlAnalysis: {status,dnsStatus,httpStatus,errors}`. Full URL/features/DNS/HTTP data is available under top-level `urlAnalysis` and `context.results.urlAnalysis`. Existing mock scores remain mock scores, untouched by this module. Future consumers must declare `dependencies: ['urlAnalysis']` before reading that result:

```ts
new Task({
  name: 'futureConsumer',
  dependencies: ['urlAnalysis'],
  run(context) {
    const analysis = context.results.urlAnalysis as UrlAnalysisResult;
    return { features: analysis.features, hostname: analysis.url?.asciiHostname };
  },
});
```

Only actual consumers need an ordering dependency. Module 4 still validates/fetches the original authorized request independently; it cannot fetch a redacted report URL or infer authorization from Module 1. Other modules should use public host/domain/features directly, or revalidate the original input before their own network operations. None should infer safety from completed/empty results.

## Testing and remaining limitations

```sh
pnpm exec tsx --test test/url-analysis-*.test.ts
pnpm typecheck
pnpm test
pnpm build
pnpm audit --prod
```

Tests use mocked record functions, Undici MockAgent with network disabled, socket/connector fixtures and local Express endpoints. No public website is required or assessed by the unit suite. Coverage includes URL/IDN/PSL/IP representations, parsing/redaction/features, DNS record types/TTLs/absence/errors/limits/timeouts, mixed public/private records, rebinding, peer mismatch, SNI/TLS settings, every supported redirect, loops/counts/domain changes, HEAD/GET fallback, declared response-size limits, stream disposal, error privacy, concurrency, cancellation, API/DAG propagation and unchanged Module 4 behavior. JSON schemas are validated using the existing Ajv development dependency.

Known limitations: no DNSSEC; TXT contents intentionally withheld; no TTL cache or address failover; no authentication/cookie sessions; no browser, meta-refresh, JavaScript or HTML-link redirect following; no complete body/integrity assessment; no continuous PSL/advisory feed (update dependencies); conservative all-address/all-family validation can block misconfigured or split-horizon DNS; redaction and metadata caps reduce exact reproduction detail. Retain original submissions only in a separately access-controlled caller system, never by copying them back into reports.

At implementation verification (2026-11-08), `pnpm typecheck`, `pnpm build`, and the full suite passed: **142 passed, 2 pre-existing opt-in Module 4 Docker tests skipped, 0 failures**. `pnpm audit --prod` reported no known vulnerabilities at that time, not a security guarantee. No live public-target assessment was performed; deployments still need controlled-environment acceptance testing with their DNS/routing/TLS configuration.
