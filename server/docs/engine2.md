# Engine 2: modular ZAP assessment

Engine 2 is separate from the retained URL analyzer and earlier web-security scanner. It implements only scope validation, traditional ZAP Spider, passive scanning and explicitly authorized active scanning. No certificate-analysis, reputation, phishing verdict or cross-engine risk score is added.

**Off by default. Crawl only targets you are authorized to test. Active ZAP rules send attack requests and may change application state, even with GET-only scope.** Deploy the API behind authentication, authorization and rate limiting; possession of a target-specific grant is not a substitute for API access control.

## Modules and workflow

| Import under `src/engines/engine2/` | Responsibility |
| --- | --- |
| `scope/index.ts` | Verify server-issued grant and token, canonicalize scope, resolve addresses; return an in-process `ApprovedScope` capability |
| `spider/index.ts` | Start/poll/stop traditional Spider; retain approved discoveries and scan ID |
| `passive/index.ts` | Configure installed passive rules, await queue completion and normalize actual alerts |
| `active/index.ts` | Apply selected installed-rule policy, scan bounded endpoints sequentially and collect scan-specific alert IDs |
| `zap/` | Per-job JSON API client, health/context setup, isolated Docker lifecycle and HTTP/HTTPS policy gateway |
| `orchestrator.ts` | Scope → passive configuration → Spider → passive completion → optional active scan → cleanup |

Each scan gets a fresh ZAP history, context, API key, gateway, interception CA and shared socket volume. Operations on one job are serialized. Independent jobs do not share client defaults or histories. The orchestrator starts active testing only when preceding modules completed; it does not escalate a passive request.

Direct imports work independently of the application DAG:

```ts
import {
  Engine2, loadEngine2Config, ScopeValidator, createDockerJobFactory,
  configurePassive, scanSpider, scanPassive, scanActive,
} from './src/engines/engine2/index.js';
import { verifyLab } from './src/engines/engine2/zap/lab.js';

const config = loadEngine2Config();
const result = await new Engine2(config).scan(request, AbortSignal.timeout(180000));

// Or own the lifecycle and call only the required modules:
const validator = new ScopeValidator(config, undefined,
  (signal) => verifyLab(config, undefined, signal));
const { scope, result: approval } = await validator.validate(request);
if (!scope) throw new Error(approval.rejectionReason ?? 'Scope rejected');
const job = await createDockerJobFactory(config)(scope, AbortSignal.timeout(config.totalTimeoutMs));
try {
  // Configure BEFORE capturing traffic; a subsequent passive read does not reconfigure.
  await configurePassive(job, scope, AbortSignal.timeout(10000));
  const spider = await scanSpider(job, scope);
  const passive = await scanPassive(job, scope);
  // Only for an already verified active capability; not needed for passive use:
  if (request.mode === 'active' && spider.status === 'completed' && passive.status === 'completed') {
    const active = await scanActive(job, scope, job.endpoints());
  }
} finally {
  await job.close();
}
```

`scanActive` also accepts an explicitly supplied approved endpoint without running Spider; it captures that endpoint with ZAP `accessUrl` first. `scanPassive` can read an existing job history without running either traffic-generating module. Serialized JSON is never accepted as an approval capability. Disabling the orchestrator does not disable direct library calls; authorization, scope and active gates remain mandatory in those modules.

## Trusted authorization configuration

Set `ENGINE2_ENABLED=true`. Configure `ENGINE2_GRANTS` as a JSON array in the **server environment**, not in submitted JSON. The server stores only each token's SHA-256 hash. Provision a cryptographically random token through a secure channel and scope it narrowly; never commit it. Grant IDs must be unique.

Example grant structure (placeholders are not usable credentials):

```json
{
  "id": "staging-approval",
  "tokenSha256": "<64 lowercase hexadecimal characters>",
  "expiresAt": "<future ISO-8601 UTC timestamp>",
  "crawlAuthorized": true,
  "rules": {
    "hosts": [{ "hostname": "staging.example.com", "includeSubdomains": false }],
    "protocols": ["https:"], "ports": [443], "paths": ["/app"],
    "excludedPaths": ["/app/private", "/app/logout", "/app/checkout"],
    "activeMethods": ["GET", "HEAD"], "profile": "public"
  },
  "allowedPolicies": ["conservative"]
}
```

For active mode, additionally set `ENGINE2_ACTIVE_ENABLED=true` and provision `activeVerification` with `verifiedBy`, `evidenceRef` and `verifiedAt`. Those fields record **an operator's prior verification** of ownership/permission; this implementation does not independently verify a DNS challenge or validate evidence documents. A user-supplied `authorized: true` flag cannot create approval. Expiry is enforced again after validation and on every outgoing gateway request. Environment grants are loaded at startup: removal/revocation requires updating/restarting the server and terminating existing labelled jobs when immediate revocation is needed.

Host matching is exact unless `includeSubdomains` is explicitly allowed, uses label boundaries, and rejects wildcard permissions at public/private suffixes or unknown suffixes. Path prefixes respect segment boundaries. Protocols and ports are independently restricted; HTTP is not silently upgraded/downgraded. Ambiguous encodings, URL credentials and fragments are rejected. Destructive path segments such as logout, delete, checkout and payment are blocked at every depth. This is a conservative guard, not a guarantee that other GET endpoints are side-effect-free.

## Application API and DAG

`POST /api/analyze` accepts an optional nested request:

```json
{
  "engine2": {
    "url": "https://staging.example.com/app",
    "mode": "passive",
    "authorizationId": "staging-approval",
    "authorizationToken": "<privately provisioned token>",
    "policy": "conservative"
  }
}
```

Use `mode: "active"` only with the active gates described above. A top-level `url` continues to invoke the existing URL analyzer/web scanner under their own configurations and permissions; omit it if requesting **only** Engine 2. Engine 2 never reuses those modules' grants.

The independent root DAG task is named `engine2`. Its whole-job retry count is explicitly zero to prevent replaying traffic-generating operations. `securityAssessment` adds a separate Engine 2 status/counts/findings/errors/limitations summary without changing mock scores. Full module results are in the top-level `engine2` output. There is no new exposed ZAP management endpoint. Expected blocked/unavailable scans are structured results, not claims of a secure target.

## Docker and network model

Requires a trusted, local **Linux Docker daemon**, Linux containers, Node 22+ for the controller, and preinstalled images. Windows users need Docker Desktop's Linux backend. The controller has host-level Docker privileges: never expose its Docker socket/API to tenants or untrusted code. Remote Docker daemons and untrusted image substitutions are outside the supported trust model.

* ZAP uses `--network none`, a loopback-only authenticated management API and a read-only shared socket/public-CA volume. Management calls use bounded `docker exec`; no host management ports are published. The small Python relay inside the existing ZAP image is transport plumbing, not a separate scanning implementation.
* The separate non-root gateway is the only egress path. HTTPS CONNECT is terminated using an ephemeral CA trusted only by that ZAP job. Decrypted requests receive full host/protocol/port/path/method/exclusion checks; upstream HTTPS certificates are validated. HTTPS URLs remain HTTPS in history and findings.
* Public targets require exclusively approved public DNS answers for each request. The connector pins the approved address and verifies the connected peer and TLS identity, without connection reuse, automatic redirects or environment proxies. Metadata, loopback, mapped/private and special-use addresses are rejected.
* The worker's private phase file permits short-lived `crawl` or `active` traffic; idle and expired phases deny traffic. Only the controller can change phases. Resource limits bound requests, bodies, duration, depth, child count and endpoints. Socket/phase errors close the job rather than leave active traffic enabled.
* Cookies, authorization, proxy credentials and arbitrary caller headers are not forwarded. Assessment is anonymous; cookie/session and header-injection coverage is intentionally limited. Request URLs and active query/body parameters still reach the target: never supply secrets in URLs or payloads.
* Both containers run UID/GID `1000:1000`, read-only root filesystems, dropped capabilities, no privilege escalation and memory/CPU/PID limits. The local tmpfs socket volume is created with matching ownership; no root bootstrap, setuid, bind mounts or Docker-socket mounts are used.
* `isolated-lab` is not a private-network override: it only permits the labelled fixture attached to one labelled internal-only Docker bridge, with no host ports or mounts. Its addresses/network identity are inspected twice and pinned. Docker administrators are trusted not to mutate that fixture/network during a job.

Jobs stop their scans, close traffic phases and remove their own resources. Cleanup failures produce `partial` plus `CLEANUP_FAILED`, and `close()` can retry remaining resources. After controller/daemon crashes, inspect resources by the returned `xerxes.engine2.job=<jobId>` label; expiry closes gateway traffic, but containers/volumes may require operator cleanup. Do not use broad Docker prune commands on a shared host.

## Isolated local fixture

The fixture deliberately reflects HTML and omits framing/CSP headers. **Do not publish its ports, add host mounts or attach external networks.** The checked-in Compose definition creates no externally accessible fixture service and does not start a persistent ZAP daemon.

From `server/`, with Docker running:

```sh
docker pull ghcr.io/zaproxy/zaproxy:stable
docker compose -f docker/engine2/compose.yaml --profile tools build gateway fixture
docker compose -f docker/engine2/compose.yaml up -d --wait fixture
node docker/engine2/create-lab-grant.mjs
node --env-file=.env.engine2.local --import tsx src/index.ts
```

The grant command creates a one-hour fixture-only grant in ignored `.env.engine2.local`, prints its private token, and refuses to overwrite an existing file. Review/remove an expired local file before regenerating. For an active fixture grant, explicitly use `node docker/engine2/create-lab-grant.mjs --active` instead. Never reuse this provisioning shortcut for production targets.

Submit the nested API request with URL `http://xerxes-engine2-fixture:8080/app`, ID `engine2-lab`, the printed token and `mode: "passive"`. The target need not resolve on the controller host: only the attested gateway connects to its pinned container address. Finish by stopping the server, then:

```sh
docker compose -f docker/engine2/compose.yaml down
```

For reproducible deployments, pin reviewed ZAP/gateway/base images by digest. The `stable` default is a convenience, not a frozen ruleset; record the digest used for acceptance. No image is automatically pulled during a scan, and runtime addon updates are disabled.

## Configuration and policies

See [`docker/engine2/.env.example`](../docker/engine2/.env.example). All configuration is server-controlled; clients cannot change budgets/images/rules.

| Variable | Default |
| --- | --- |
| `ENGINE2_ENABLED`, `ENGINE2_ACTIVE_ENABLED` | `false`, `false` |
| `ENGINE2_GRANTS` | `[]` |
| `ENGINE2_TOTAL_TIMEOUT_MS`, `ENGINE2_STARTUP_TIMEOUT_MS` | `180000`, `45000` |
| `ENGINE2_SPIDER_TIMEOUT_MS`, `ENGINE2_PASSIVE_TIMEOUT_MS`, `ENGINE2_ACTIVE_TIMEOUT_MS` | `45000`, `30000`, `60000` |
| `ENGINE2_API_TIMEOUT_MS`, `ENGINE2_REQUEST_TIMEOUT_MS`, `ENGINE2_POLL_INTERVAL_MS` | `5000`, `5000`, `500` |
| `ENGINE2_REQUEST_INTERVAL_MS`, `ENGINE2_MAX_REQUESTS`, `ENGINE2_MAX_RESPONSE_BYTES` | `250`, `100`, `1048576` |
| `ENGINE2_MAX_DEPTH`, `ENGINE2_MAX_CHILDREN`, `ENGINE2_MAX_ENDPOINTS` | `3`, `10`, `100` |
| `ENGINE2_MAX_ACTIVE_ENDPOINTS`, `ENGINE2_MAX_FINDINGS`, `ENGINE2_MAX_CONCURRENT_SCANS` | `3`, `500`, `2` |
| `ENGINE2_PASSIVE_RULE_IDS` | `[]`: keep installed defaults; nonempty JSON array selects rule IDs |
| `ENGINE2_POLICIES` | `conservative`: IDs `40012`, `40018`, `10028`; LOW strength, MEDIUM threshold |
| `ENGINE2_ZAP_IMAGE`, `ENGINE2_GATEWAY_IMAGE` | `ghcr.io/zaproxy/zaproxy:stable`, `xerxes-engine2-gateway:local` |
| `ENGINE2_LAB_NETWORK`, `ENGINE2_LAB_TARGET` | `xerxes-engine2-lab`, `xerxes-engine2-fixture` |

Policies are JSON arrays of `{ name, ruleIds, strength, threshold }`. Rules must already exist in the selected ZAP image; missing addons/API operations are explicit failures, never an invitation to download code or substitute custom detection. The default request-body ceiling is fixed at 64 KiB. Passive/active timeouts bound operations, not just status polling. A separate bounded read-only cleanup budget can extend result collection beyond the main timeout.

## Results and limitations

Every module has `status`, `errors`, duration and limitations. Overall statuses are `completed`, `partial`, `blocked`, `failed`, `cancelled`, `skipped` and `unavailable`. Completed zero alerts means only that the configured operations finished on observed traffic; no traffic, pending queues, malformed/API-failed responses, policy denials and exhausted budgets cannot be reported as complete zero-alert coverage. Partial pagination and timeout paths retain alerts already collected. Historical passive collection remains possible after grant expiry, but no new target traffic is authorized.

Findings retain ZAP plugin/alert IDs, passive/active provenance, endpoint, method/parameter provenance, description, remediation, references, severity and confidence. False-positive alerts and out-of-scope URLs are excluded. CWE/OWASP tags are derived only where supplied/supported; there are no invented CVEs or CVSS scores. Raw matched evidence, payloads, cookies and `otherInfo` are withheld; output includes evidence byte count and reproducibility identifiers instead. Existing redaction helpers sanitize URLs/text; treat results as sensitive operational data regardless.

ZAP source IDs are active `1`, passive `3`. Passive results expose `pendingRecords` and actual job-history `observedMessages`; exact `analysedMessages` is `null` because ZAP's queue API does not provide that measurement. Active results are collected using that scan's alert IDs, not unrelated history. Passive findings in the combined workflow describe traffic captured before active scans.

Traditional Spider only: no Ajax/browser exploration, authentication, credential/cookie forwarding, OAST, recursive active scanning or custom vulnerability algorithms. Single-flight/rate limits, conservative exclusions and bounded response handling deliberately trade coverage for containment. Some installed ZAP rules will not work within these restrictions; timeouts/denials yield incomplete results, not relaxed policy.

## Verification

```sh
pnpm typecheck
pnpm test
pnpm build
pnpm audit --prod
```

Default tests use scripted APIs and local HTTP/TLS fixtures, not public scanning. Real Docker tests are opt-in and accept only the fixed isolated fixture:

```sh
# After building images and starting the fixture above:
ENGINE2_DOCKER_TESTS=true pnpm exec tsx --test test/engine2-integration.test.ts
```

PowerShell: set `$env:ENGINE2_DOCKER_TESTS='true'`, run the `pnpm exec` command, then `Remove-Item Env:ENGINE2_DOCKER_TESTS`. Opted-in tests fail (rather than silently skip) when the daemon/images/fixture are missing. They check real Spider discoveries, passive anti-clickjacking alerts, selected reflected-XSS active alerts, gateway scope denial and resource cleanup.

**Live Docker builds/ZAP acceptance have not been verified in the implementation environment: Docker Desktop's Linux daemon was unavailable.** Passing unit/local TLS tests do not establish compatibility of the chosen ZAP image. Run the opt-in suite on your Linux daemon before deployment.

Implementation verification: full suite **209 passed, 4 Docker tests skipped** (two retained scanner tests and two Engine 2 tests); typecheck, build, production dependency audit, Compose configuration validation and fixture/provisioning script syntax checks passed. The audit reported no known production dependency vulnerabilities.
