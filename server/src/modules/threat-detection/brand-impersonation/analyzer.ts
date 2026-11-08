import { domainToASCII, domainToUnicode } from 'node:url';
import { remove as removeConfusables } from 'confusables';
import { distance } from 'fastest-levenshtein';
import { domainParts, parseHttpUrl } from '../shared/url.js';

import type { BrandDefinition, BrandImpersonationFinding, BrandImpersonationResult } from './types.js';

export type { BrandDefinition, BrandImpersonationFinding, BrandImpersonationResult } from './types.js';

function skeleton(value: string): string {
  return removeConfusables(value.normalize('NFKC')).toLowerCase();
}

/**
 * Offline catalog-based indicators, not a verdict. The caller maintains the official-domain catalog.
 * Confusable folding is approximate; unrelated sites can legitimately contain brand-like words.
 */
export function createBrandImpersonationDetector(
  brands: readonly BrandDefinition[],
  options: { maxEditDistance?: number } = {},
): (input: string) => BrandImpersonationResult {
  const maxEditDistance = options.maxEditDistance ?? 1;
  if (!Number.isInteger(maxEditDistance) || maxEditDistance < 1 || maxEditDistance > 2) {
    throw new TypeError('maxEditDistance must be 1 or 2');
  }
  const catalog = brands.map((brand) => {
    if (typeof brand.name !== 'string' || !brand.name.trim() || !brand.domains.length) {
      throw new TypeError('Each brand needs a name and at least one official domain');
    }
    const domains = brand.domains.map((domain) => {
      if (typeof domain !== 'string' || !domain || /[\s/:@?#\\]/u.test(domain)) {
        throw new TypeError('Official domains must be bare domain names');
      }
      const ascii = domainToASCII(domain.toLowerCase().replace(/\.$/, ''));
      if (!ascii || ascii.split('.').some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
        throw new TypeError('Invalid official domain');
      }
      const parts = domainParts(parseHttpUrl(`https://${ascii}`));
      if (parts.isIp || parts.domain !== ascii || !parts.domainWithoutSuffix) {
        throw new TypeError('Official domains must be registrable domains, not IPs, suffixes, or subdomains');
      }
      return { domain: ascii, label: skeleton(domainToUnicode(parts.domainWithoutSuffix)) };
    });
    return {
      name: brand.name.trim(), domains,
      tokens: [...new Set([skeleton(brand.name).replace(/[^a-z0-9]/g, ''), ...domains.map((domain) => domain.label)])]
        .filter((token) => token.length >= 4),
    };
  });

  return (input) => {
    const url = parseHttpUrl(input);
    const parts = domainParts(url);
    const findings: BrandImpersonationFinding[] = [];
    if (!parts.isIp && parts.domain && parts.domainWithoutSuffix) {
      const unicodeLabel = domainToUnicode(parts.domainWithoutSuffix);
      const label = skeleton(unicodeLabel);
      const subdomain = skeleton(domainToUnicode(parts.subdomain ?? ''));
      for (const brand of catalog) {
        if (brand.domains.some(({ domain }) => parts.hostname === domain || parts.hostname.endsWith(`.${domain}`))) continue;
        const add = (reason: BrandImpersonationFinding['reason'], observed: string, editDistance?: number) => {
          findings.push({ brand: brand.name, reason, observed, officialDomains: brand.domains.map(({ domain }) => domain),
            ...(editDistance === undefined ? {} : { editDistance }) });
        };
        const confusable = /[^\x00-\x7f]/u.test(unicodeLabel)
          && brand.domains.some((domain) => domain.label === label);
        if (confusable) {
          add('unicode_confusable', unicodeLabel);
        } else if (brand.tokens.some((token) => label.includes(token))) {
          add('brand_in_domain', unicodeLabel);
        } else {
          const distances = brand.domains
            .filter((domain) => domain.label.length >= 5 && label.length >= 5)
            .map((domain) => distance(label, domain.label));
          const closest = Math.min(...distances);
          if (closest > 0 && closest <= maxEditDistance) add('domain_typo', unicodeLabel, closest);
        }
        if (brand.tokens.some((token) => subdomain.includes(token))) {
          add('deceptive_subdomain', parts.subdomain!);
        }
      }
    }
    return { normalizedUrl: url.href, registrableDomain: parts.domain, brandsChecked: catalog.length, findings };
  };
}
