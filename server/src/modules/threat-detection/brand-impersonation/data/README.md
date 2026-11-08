# Zenodo brand catalog

## Attribution and license

Putra, I Kadek Agus Ariesta (2023). **Phishing Website Dataset**, version 1,
Zenodo. DOI: [10.5281/zenodo.8041387](https://doi.org/10.5281/zenodo.8041387).

- Record: https://zenodo.org/records/8041387
- Source: https://zenodo.org/records/8041387/files/brands.csv?download=1
- License: [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/)
- Import date: **2026-11-08**
- Original `brands.csv`: **16,951 bytes**, unmodified; published MD5:
  `4194175e26f89582dd0a641b34f897de`.

The CSV and derived `../catalog.ts` are covered by this dataset attribution and
license. The catalog is a transformed subset, not the original dataset. No
endorsement by the dataset author or listed organizations is implied. Only the
small brand CSV was downloaded; no website archives or website-level CSVs were
downloaded or included.

## Transformation and exclusions

`generate-catalog.py` parses UTF-8 CSV with Python's standard-library `csv.DictReader`
(including quoted commas and doubled quotes). It uses **only `name` and `website`**
for mappings; `identifier` is used to exclude the four known non-brand placeholders.
Descriptions and categories do not provide domains. Names are trimmed but otherwise
preserved, including accents and apparent source typos.

Websites are trimmed and validated as explicit HTTP(S) URLs using the existing
application URL parser. Malformed DNS labels, IPs, credentials, missing websites
(including `-`), and hosts without a recognized ICANN/private suffix and registrable
domain are rejected. The existing `tldts` dependency (with private suffixes enabled,
as in the detector) extracts lowercase ASCII registrable domains: scheme, port,
path, query, fragment, `www`, and all other subdomains are discarded. For example:

- `https://www.anz.com.au/personal/` → `anz.com.au`
- `https://www3.mtb.com/` → `mtb.com`
- `https://onedrive.live.com/` → `live.com`
- `https://www.impots.gouv.fr/` → `impots.gouv.fr` (not `gouv.fr`)

Identical trimmed brand names are merged in first-seen order and normalized
domains are deduplicated per brand. No domains are guessed, corrected, fetched,
or supplemented with alternate/regional domains.

| Excluded identifier | Source name | Reason |
| --- | --- | --- |
| `excelpdfdownload` | Excel PDF Download | Non-brand download template; website `-` |
| `generic` | Generic | Generic target; website `-` |
| `genericcrypto` | Generic Crypto | Generic target; website `-` |
| `genericemail` | Generic Email | Generic target; website `-` |

Totals: **86 source rows**, **4 excluded**, **82 retained brands**, **82 unique
domains** (one per brand). There are no additional missing-site/malformed-domain
exclusions, merged names, or duplicate domains in this snapshot. Named public
services (e.g. Australian Government) are retained as identifiable impersonation
targets; the `Other` category alone is not grounds for exclusion.

## Reproduction (offline)

With Python 3.10+ and the project's existing Node development dependencies installed,
run from `server/`:

```sh
python3 src/modules/threat-detection/brand-impersonation/data/generate-catalog.py --check
```

Without `--check`, the script prints the generated TypeScript to stdout and totals
and exclusions to stderr. It checks the published source checksum before importing
and makes no network requests. Review changes before replacing `catalog.ts`; a
different source snapshot requires an explicit checksum and documentation update.
Suffix-list changes in `tldts` can affect regeneration.

## Explicit opt-in

Import `ZENODO_BRAND_CATALOG` from the brand-impersonation public `index.ts`:

```ts
const detect = createBrandImpersonationDetector(ZENODO_BRAND_CATALOG);
// Or, in caller-supplied pipeline options:
const options = { brandImpersonation: { brands: ZENODO_BRAND_CATALOG } };
```

The catalog is never implicitly wired into detector/pipeline defaults. The standard
HTTP server entry point now selects it explicitly for `/api/analyze`; other callers
still choose their own configuration. Omitted configuration and an explicit empty
catalog continue to check zero brands.

## Known limitations

- This is a small 2023 research snapshot, not a complete or current authoritative
  brand/domain directory. Domain ownership, availability, redirects, and source
  mappings have not been independently verified. No live brand sites were queried.
- Source inconsistencies are retained, not silently repaired: e.g. `AAT&T Inc.`
  and the `Aruba Networks` / `arubacloud.com` mapping. Review these before operational
  use; this import validates structure, not factual ownership.
- Reducing product hosts to registrable domains broadens the detector's official
  domain exemption: OneDrive becomes `live.com`, so all subdomains of that domain
  are exempt for that brand. Product isolation is lost.
- Most alternate domains and regional sites are absent. Missing legitimate domains
  can cause false positives; absent brands and heuristic matching can cause false
  negatives. Brand findings are indicators, not safety/phishing verdicts.
- No site contents, phishing examples, model training, or accuracy claims are
  included. Runtime consumption is a static TypeScript import, not CSV parsing.
