import type { Evidence } from '../contracts/evidence.js';
import type { AssessmentOptions, AssessmentRule, Finding } from './types.js';

function groupByTarget(evidence: readonly Evidence[]): Evidence[][] {
  const groups = new Map<string, Evidence[]>();
  for (const item of evidence) {
    const key = `${item.target}:${item.hostname}`;
    const group = groups.get(key) ?? [];
    group.push(item);
    groups.set(key, group);
  }
  return [...groups.values()];
}

/** Explicit policy rules, not a learned or calibrated probability model. */
export function createAssessmentRules(options: AssessmentOptions = {}): AssessmentRule[] {
  const trusted = new Set(options.trustedBlacklistSources ?? []);
  return [
    {
      id: 'blacklist-match',
      evaluate: (evidence) => groupByTarget(evidence).flatMap((group): Finding[] => {
        const matches = group.filter((item) => item.code === 'BLACKLIST_MATCH');
        if (!matches.length) return [];
        const trustedMatch = matches.some((item) => trusted.has(item.source));
        return [{ ruleId: 'blacklist-match', severity: trustedMatch ? 'high' : 'medium',
          message: trustedMatch ? 'A trusted blacklist source reported a match.'
            : 'A configured blacklist source reported a match; it is not designated trusted by this assessment policy.',
          evidence: matches }];
      }),
    },
    {
      id: 'brand-impersonation',
      evaluate: (evidence) => groupByTarget(evidence).flatMap((group): Finding[] => {
        const brands = group.filter((item) => item.code === 'BRAND_LOOKALIKE');
        if (!brands.length) return [];
        const supporting = group.filter((item) =>
          (item.code === 'AUTH_KEYWORD' && (item.location === 'path' || item.location === 'query')
            && item.keywords.some((word) => /^(?:login|signin|verify|verification|password|account|wallet|recover)$/.test(word)))
          || (item.code === 'ML_PREDICTION' && item.probability >= item.threshold));
        return [{ ruleId: 'brand-impersonation', severity: supporting.length ? 'medium' : 'info',
          message: supporting.length ? 'Brand-lookalike evidence is accompanied by authentication terms or a model signal on the same target; possible impersonation requires review.'
            : 'Hostname resembles a configured brand; resemblance alone does not establish impersonation.',
          evidence: [...brands, ...supporting] }];
      }),
    },
    {
      id: 'redirect-behavior',
      evaluate: (evidence) => groupByTarget(evidence).flatMap((group): Finding[] => {
        const hops = group.filter((item) => item.code === 'REDIRECT_HOP'
          && (item.crossDomain || (item.fromScheme === 'https:' && item.toScheme === 'http:')));
        if (!hops.length) return [];
        const downgrade = hops.some((item) => item.code === 'REDIRECT_HOP' && item.fromScheme === 'https:' && item.toScheme === 'http:');
        return [{ ruleId: 'redirect-behavior', severity: downgrade ? 'medium' : 'info',
          message: downgrade ? 'An HTTPS redirect points to HTTP, reducing transport protection; this is not proof of phishing.'
            : 'Redirect chain points to another registrable domain; cross-domain redirects can be legitimate.',
          evidence: hops }];
      }),
    },
    {
      id: 'url-structure',
      evaluate: (evidence) => groupByTarget(evidence).flatMap((group): Finding[] => {
        const hasBrand = group.some((item) => item.code === 'BRAND_LOOKALIKE');
        const observations = group.filter((item) =>
          (item.code === 'URL_STRUCTURE' && !(hasBrand && item.signal === 'punycode'))
          || (!hasBrand && item.code === 'AUTH_KEYWORD'));
        if (!observations.length) return [];
        const credentials = observations.some((item) => item.code === 'URL_STRUCTURE' && item.signal === 'credentials');
        return [{ ruleId: 'url-structure', severity: credentials ? 'medium' : 'info',
          message: credentials ? 'URL contains embedded user information, which can obscure the actual destination.'
            : 'Structural URL indicators were observed; individually or together these do not establish phishing.',
          evidence: observations }];
      }),
    },
    {
      id: 'ml-signal',
      evaluate: (evidence) => groupByTarget(evidence).flatMap((group): Finding[] => {
        if (group.some((item) => item.code === 'BRAND_LOOKALIKE')) return [];
        const predictions = group.filter((item) => item.code === 'ML_PREDICTION' && item.probability >= item.threshold);
        return predictions.length ? [{ ruleId: 'ml-signal', severity: 'info',
          message: 'The URL model estimate exceeded its configured threshold; model accuracy and calibration must be evaluated separately.',
          evidence: predictions }] : [];
      }),
    },
  ];
}
