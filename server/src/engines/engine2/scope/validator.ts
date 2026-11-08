import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { publicAddress, resolvePublic, type Resolver } from '../../../shared/network/policy.js';
import { safeUrl } from '../../../shared/security/redaction.js';
import { requestSchema, type Engine2Config, type Engine2ScanRequest, type ScopeRules, type ScopeValidationResult } from '../types.js';
import { Engine2Failure, scanError } from '../errors.js';
import { checkScope, normalizedRules, scopeUrl } from './rules.js';
import { verifyAuthorization } from './authorization.js';
import { resolveAddresses } from '../zap/gateway-transport.js';

export interface LabAttestation { networkId: string; addresses: string[]; hostname: string; }
export type LabVerifier = (signal?: AbortSignal) => Promise<LabAttestation>;
const capability = Symbol('approved-engine2-scope');
/** Runtime capability: a JSON object with approved:true is never accepted by scanning modules. */
export class ApprovedScope {
  readonly id = randomUUID();
  readonly #rulesValue: ScopeRules;
  readonly #target: string;
  readonly request: Readonly<Pick<Engine2ScanRequest, 'mode' | 'policy' | 'authorizationId'>>;
  constructor(key: symbol, target: string, request: Engine2ScanRequest, rules: ScopeRules,
    readonly expiresAt: number, readonly lab: Readonly<LabAttestation> | null) {
    if (key !== capability) throw new Engine2Failure('UNAPPROVED_SCOPE', 'Scope approval capability required');
    this.#target = target;
    this.request = { mode: request.mode, policy: request.policy, authorizationId: request.authorizationId };
    this.#rulesValue = structuredClone(rules);
    if (lab) { this.lab = structuredClone(lab); Object.freeze(this.lab.addresses); Object.freeze(this.lab); }
    Object.freeze(this.request); Object.freeze(this);
  }
  get target(): string { return this.#target; }
  get rules(): ScopeRules { return structuredClone(this.#rulesValue); }
  toJSON() { return { scopeId: this.id }; }
  includes(url: string | URL) { return checkScope(url, this.#rulesValue); }
  check(url: string | URL) {
    if (Date.now() >= this.expiresAt) return { allowed: false, reason: 'AUTHORIZATION_EXPIRED' };
    return checkScope(url, this.#rulesValue);
  }
  assert(url: string | URL): void {
    const decision = this.check(url);
    if (!decision.allowed) throw new Engine2Failure(decision.reason!, 'Endpoint is outside current authorized scope');
  }
  static assert(value: unknown): asserts value is ApprovedScope {
    if (!(value instanceof ApprovedScope)) throw new Engine2Failure('UNAPPROVED_SCOPE', 'A validated in-process scope capability is required');
    value.assert(value.target);
  }
}
export function emptyScope(): ScopeValidationResult {
  return { status: 'skipped', errors: [], approved: false, normalizedTarget: null, authorizedMode: null, allowedHosts: [], excludedPaths: [], scopeId: null, contextId: null, rejectionReason: null, limitations: [] };
}
export class ScopeValidator {
  constructor(private readonly config: Engine2Config, private readonly resolver?: Resolver, private readonly verifyLab?: LabVerifier) {}
  async validate(input: unknown, parent: AbortSignal = new AbortController().signal): Promise<{ result: ScopeValidationResult; scope: ApprovedScope | null }> {
    const result = emptyScope();
    const signal = AbortSignal.any([parent, AbortSignal.timeout(this.config.requestTimeoutMs)]);
    try {
      signal.throwIfAborted();
      const parsed = requestSchema.safeParse(input);
      if (!parsed.success) throw new Engine2Failure('INVALID_REQUEST', 'Invalid Engine 2 URL, mode or authorization request');
      const request = parsed.data;
      const grant = verifyAuthorization(request, this.config); // Permission before even a DNS query.
      const target = scopeUrl(request.url);
      const rules = normalizedRules(grant.rules);
      const decision = checkScope(target, rules);
      if (!decision.allowed) throw new Engine2Failure(decision.reason!, 'Target is outside the authorized scope');
      const host = target.hostname.replace(/^\[|\]$/g, '');
      let lab: LabAttestation | null = null;
      if (rules.profile === 'isolated-lab') {
        if (!this.verifyLab) throw new Engine2Failure('LAB_NOT_ISOLATED', 'Isolated development network verification unavailable');
        lab = await this.verifyLab(signal);
        if (host !== lab.hostname || !lab.addresses.length || rules.hosts.some((h) => h.includeSubdomains || h.hostname !== lab!.hostname)) throw new Engine2Failure('LAB_SCOPE_MISMATCH', 'Development grants may only target the verified fixture container');
      } else {
        if (/(?:^|\.)(?:localhost|local|internal|home|lan|test|invalid|onion)\.?$/i.test(host) || host.endsWith('.') || (isIP(host) && !publicAddress(host))) throw new Engine2Failure('NETWORK_BLOCKED', 'Prohibited target hostname or address');
        await new Promise<void>((resolve, reject) => {
          const aborted = () => reject(signal.reason);
          signal.addEventListener('abort', aborted, { once: true });
          if (signal.aborted) aborted();
          resolvePublic(target, this.resolver ?? ((hostname) => resolveAddresses(hostname, signal))).then(() => resolve(), () => reject(new Engine2Failure('NETWORK_BLOCKED', 'DNS did not provide exclusively approved public addresses'))).finally(() => signal.removeEventListener('abort', aborted));
        });
      }
      signal.throwIfAborted();
      verifyAuthorization(request, this.config); // DNS/attestation must not outlive the grant.
      const scope = new ApprovedScope(capability, target.href, request, rules, Date.parse(grant.expiresAt), lab);
      Object.assign(result, { status: 'completed', approved: true, normalizedTarget: safeUrl(target.href), authorizedMode: request.mode,
        allowedHosts: rules.hosts, excludedPaths: rules.excludedPaths.map((path) => new URL(safeUrl(`https://scope.invalid${path}`)).pathname), scopeId: scope.id,
        limitations: ['Authorization is operator-provisioned; a client consent flag does not establish ownership.', 'DNS and scope are rechecked at the gateway for every actual request.'] });
      return { result, scope };
    } catch (error) {
      const observed = scanError('scope', error, signal);
      result.status = signal.aborted ? 'cancelled' : 'blocked'; result.errors.push(observed); result.rejectionReason = observed.code;
      return { result, scope: null };
    }
  }
}
