import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { parse } from 'tldts';
import {
  createBrandImpersonationDetector, ZENODO_BRAND_CATALOG,
} from '../src/modules/threat-detection/brand-impersonation/index.js';
import type { BrandDefinition } from '../src/modules/threat-detection/brand-impersonation/index.js';
import { ZENODO_BRAND_CATALOG as directCatalog } from '../src/modules/threat-detection/brand-impersonation/catalog.js';

// This assignment also checks that the public catalog fits the existing caller API.
const catalog: readonly BrandDefinition[] = ZENODO_BRAND_CATALOG;

test('public Zenodo catalog export has the expected shape and unique names/domains', () => {
  assert.strictEqual(catalog, directCatalog);
  assert.equal(catalog.length, 82);
  const names = new Set<string>();
  const domains = new Set<string>();
  for (const brand of catalog) {
    assert.deepEqual(Object.keys(brand).sort(), ['domains', 'name']);
    assert.equal(typeof brand.name, 'string');
    assert.ok(brand.name.length > 0);
    assert.equal(brand.name, brand.name.trim());
    assert.ok(!names.has(brand.name.toLowerCase()), `Duplicate brand: ${brand.name}`);
    names.add(brand.name.toLowerCase());
    assert.ok(Array.isArray(brand.domains));
    assert.ok(brand.domains.length > 0);
    assert.equal(new Set(brand.domains).size, brand.domains.length);
    for (const domain of brand.domains) {
      assert.equal(typeof domain, 'string');
      assert.equal(domain, domain.toLowerCase());
      assert.ok(domain.length <= 253);
      assert.ok(!domain.startsWith('www.'));
      assert.match(domain, /^[a-z0-9.-]+$/);
      for (const label of domain.split('.')) {
        assert.match(label, /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/);
      }
      const parts = parse(domain, { allowPrivateDomains: true });
      assert.equal(parts.isIp, false);
      assert.ok(parts.isIcann || parts.isPrivate);
      assert.equal(parts.domain, domain, `Not registrable: ${domain}`);
      assert.equal(parts.subdomain, '');
      assert.ok(!domains.has(domain), `Duplicate domain: ${domain}`);
      domains.add(domain);
    }
  }
  assert.equal(domains.size, 82);
  assert.doesNotThrow(() => createBrandImpersonationDetector(catalog));
});

test('retained source is byte-exact and representative mappings/exclusions are preserved', () => {
  const source = readFileSync(new URL(
    '../src/modules/threat-detection/brand-impersonation/data/brands.csv', import.meta.url,
  ));
  assert.equal(source.length, 16_951);
  assert.equal(createHash('md5').update(source).digest('hex'), '4194175e26f89582dd0a641b34f897de');
  const byName = new Map(catalog.map((brand) => [brand.name, brand.domains]));
  // Quoted commas in descriptions must not shift the website column.
  assert.deepEqual(byName.get('1&1 IONOS'), ['ionos.com']);
  assert.deepEqual(byName.get('Amazon'), ['amazon.com']);
  assert.deepEqual(byName.get('ANZ Bank'), ['anz.com.au']);
  assert.deepEqual(byName.get('Banco Industrial'), ['corporacionbi.com']);
  assert.deepEqual(byName.get('M&T Bank'), ['mtb.com']);
  assert.deepEqual(byName.get('OneDrive'), ['live.com']);
  assert.deepEqual(byName.get('Steam'), ['steampowered.com']);
  assert.deepEqual(byName.get('impotsgouv'), ['impots.gouv.fr']);
  assert.deepEqual(byName.get('PayPal'), ['paypal.com']); // No invented alternate domains.
  for (const name of ['Excel PDF Download', 'Generic', 'Generic Crypto', 'Generic Email']) {
    assert.equal(byName.has(name), false);
  }
});

test('dataset detector exempts official domains and subdomains for their respective brands', () => {
  const detect = createBrandImpersonationDetector(catalog);
  for (const brand of catalog) {
    for (const domain of brand.domains) {
      for (const hostname of [domain, `login.${domain}`]) {
        const result = detect(`https://${hostname}/`);
        assert.equal(result.brandsChecked, 82);
        assert.ok(!result.findings.some((finding) => finding.brand === brand.name), hostname);
      }
    }
  }
});

test('dataset detector identifies a PayPal typo and Unicode lookalike offline', () => {
  const detect = createBrandImpersonationDetector(catalog);
  assert.deepEqual(detect('https://www.paypal.com/login').findings, []);
  assert.ok(detect('https://paypaal.com/').findings.some((finding) =>
    finding.brand === 'PayPal' && finding.reason === 'domain_typo'
    && finding.editDistance === 1 && finding.officialDomains.join() === 'paypal.com'));
  assert.ok(detect('https://раypal.com/').findings.some((finding) =>
    finding.brand === 'PayPal' && finding.reason === 'unicode_confusable'));
  const empty = createBrandImpersonationDetector([])('https://paypaal.com/');
  assert.equal(empty.brandsChecked, 0);
  assert.deepEqual(empty.findings, []);
});
