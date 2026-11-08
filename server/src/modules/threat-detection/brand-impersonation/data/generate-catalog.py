"""Offline importer: run from any directory with Python 3 and server dependencies installed.

Prints catalog.ts to stdout, or verifies it with --check. Never fetches source data.
"""

import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys


DATA = Path(__file__).resolve().parent
SERVER = DATA.parents[4]
SOURCE_MD5 = "4194175e26f89582dd0a641b34f897de"
NON_BRANDS = {"excelpdfdownload", "generic", "genericcrypto", "genericemail"}


def generate():
    source = (DATA / "brands.csv").read_bytes()
    if hashlib.md5(source).hexdigest() != SOURCE_MD5:
        raise ValueError("Source differs from the published Zenodo brands.csv; review before importing")
    # csv handles quoted commas, escaped quotes, and embedded newlines.
    rows = list(csv.DictReader(io.StringIO(source.decode("utf-8"), newline=""), strict=True))
    if any(None in row or None in row.values() for row in rows):
        raise ValueError("Malformed CSV row")

    # Reuse the application's URL validation and suffix policy, without DNS/HTTP calls.
    result = subprocess.run(
        ["node", "--import", "tsx", "--input-type=module", "-e", """
import { readFileSync } from 'node:fs';
import { parse } from 'tldts';
import { domainParts, parseHttpUrl } from './src/modules/threat-detection/shared/url.ts';
const domains = JSON.parse(readFileSync(0, 'utf8')).map((website) => {
  try {
    const url = parseHttpUrl(website.trim());
    if (url.username || url.password) return null;
    const parts = domainParts(url);
    const suffix = parse(parts.hostname, { allowPrivateDomains: true });
    if (parts.isIp || !parts.domain || !(suffix.isIcann || suffix.isPrivate)) return null;
    return parts.domain;
  } catch { return null; }
});
console.log(JSON.stringify(domains));
"""],
        cwd=SERVER, input=json.dumps([row["website"] for row in rows]),
        text=True, capture_output=True, check=True,
    )
    brands = {}
    excluded = []
    for row, domain in zip(rows, json.loads(result.stdout), strict=True):
        name = row["name"].strip()
        if row["identifier"] in NON_BRANDS:
            excluded.append((row["identifier"], "generic/non-brand placeholder; no website"))
        elif not name or not domain:
            excluded.append((row["identifier"], "missing name or unusable website/domain"))
        else:
            # Preserve first-seen brand order, merging identical names and deduplicating domains.
            brands.setdefault(name, {})[domain] = None

    lines = [
        "// Generated from data/brands.csv; see data/README.md for attribution and limitations.",
        "// Putra (2023), DOI: 10.5281/zenodo.8041387, CC BY 4.0.",
        "import type { BrandDefinition } from './types.js';",
        "",
        "/** Optional dataset catalog; never applied automatically. */",
        "export const ZENODO_BRAND_CATALOG = [",
    ]
    for name, domains in brands.items():
        lines.append("  { name: " + json.dumps(name, ensure_ascii=False)
                     + ", domains: " + json.dumps(list(domains)) + " },")
    lines.extend(["] as const satisfies readonly BrandDefinition[];", ""])
    print(f"{len(rows)} source rows; {len(brands)} brands; "
          f"{sum(map(len, brands.values()))} domains; {len(excluded)} exclusions", file=sys.stderr)
    for identifier, reason in excluded:
        print(f"  {identifier}: {reason}", file=sys.stderr)
    return "\n".join(lines)


if __name__ == "__main__":
    catalog = generate()
    if sys.argv[1:] == ["--check"]:
        if (DATA.parent / "catalog.ts").read_text() != catalog:
            sys.exit("catalog.ts is out of date")
    elif sys.argv[1:]:
        sys.exit("Usage: python3 generate-catalog.py [--check]")
    else:
        print(catalog, end="")
