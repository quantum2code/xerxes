import semver from 'semver';
import type { Check } from '../types.js';
import { header, observation } from './helpers.js';

// Deliberately small, reviewable advisory snapshot. Never infer versions from filenames/CDN URLs.
// GHSA-gxr4-xjj5-5px2: https://github.com/advisories/GHSA-gxr4-xjj5-5px2
export const dependencies: Check = {
  id: 'dependencies',
  run(page) {
    if (!/(?:javascript|ecmascript|text\/plain)/i.test(header(page, 'content-type'))) return [];
    const version = /\/\*!?\s*jQuery(?: JavaScript Library)?\s+v?(\d+\.\d+\.\d+)\b/i.exec(page.body.slice(0, 4096))?.[1];
    if (!version || !semver.valid(version) || !semver.satisfies(version, '>=1.12.0 <3.5.0')) return [];
    return [{ ...observation(page, this.id, 'jQuery version affected by published XSS advisory',
      'The fetched JavaScript banner identifies a version within the advisory range. Banners can be stale or forged; vulnerable API use and exploitability were not verified.',
      `JavaScript banner: jQuery ${version}; advisory GHSA-gxr4-xjj5-5px2 (>=1.12.0 <3.5.0)`, 'medium', ['CWE-79'],
      'Upgrade jQuery to a supported release at least 3.5.0, and review untrusted HTML processing. Advisory: https://github.com/advisories/GHSA-gxr4-xjj5-5px2'),
      confidence: 'medium' as const, owasp: ['A06:2021'], cves: ['CVE-2020-11022'] }];
  },
};
