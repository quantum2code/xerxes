import type { Check, FindingInput } from '../types.js';
import { header, isHtml, observation } from './helpers.js';

export const securityHeaders: Check = {
  id: 'security-headers',
  run(page) {
    const findings: FindingInput[] = [];
    const add = (title: string, evidence: string, remediation: string) => findings.push(observation(page, this.id, title,
      'This is a defense-in-depth configuration observation, not evidence of a successful exploit.', evidence, 'low', [], remediation));
    if (isHtml(page)) {
      const csp = header(page, 'content-security-policy');
      const policies = csp.split(',').map((policy) => new Map(policy.split(';').map((d) => {
        const [name = '', ...values] = d.trim().split(/\s+/); return [name.toLowerCase(), values];
      })));
      if (!csp) add('Content Security Policy not observed', 'No enforcing Content-Security-Policy response header', 'Deploy an enforcing CSP with nonces or hashes; report-only policies do not enforce restrictions.');
      else if (policies.every((p) => {
        const script = p.get('script-src') ?? p.get('default-src');
        return !script || script.includes('*') || script.includes("'unsafe-eval'") ||
          (script.includes("'unsafe-inline'") && !script.some((s) => /^'(?:nonce-|sha(?:256|384|512)-)/.test(s)));
      })) add('Potentially permissive script policy', 'No observed CSP policy provides a restrictive script-src/default-src', 'Review script policy semantics and restrict script sources; prefer nonces or hashes.');
      const xfo = header(page, 'x-frame-options').trim().toLowerCase();
      const ancestors = policies.some((p) => {
        const values = p.get('frame-ancestors');
        return values && values.length > 0 && !values.includes('*');
      });
      if (!ancestors && !['deny', 'sameorigin'].includes(xfo)) add('Framing restriction not observed', 'No restrictive frame-ancestors or valid X-Frame-Options header', 'Set CSP frame-ancestors and, where needed, X-Frame-Options. Actual clickjacking risk depends on sensitive UI exposure.');
      const referrer = header(page, 'referrer-policy').split(',').map((v) => v.trim()).filter(Boolean).at(-1);
      if (!referrer || ['unsafe-url', 'no-referrer-when-downgrade'].includes(referrer)) add('Referrer policy absent or permissive', referrer ? `Referrer-Policy: ${referrer}` : 'Referrer-Policy header absent', 'Set strict-origin-when-cross-origin or a stricter policy. Browser defaults may already reduce exposure.');
    }
    if (header(page, 'x-content-type-options').trim().toLowerCase() !== 'nosniff') add('MIME sniffing protection not observed', 'X-Content-Type-Options is absent or not nosniff', 'Send X-Content-Type-Options: nosniff with correct content types.');
    if (new URL(page.url).protocol === 'https:') {
      const hsts = header(page, 'strict-transport-security');
      const maxAge = /(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i.exec(hsts);
      if (!maxAge || Number(maxAge[1]) === 0) add('HSTS protection not observed', hsts ? 'HSTS lacks a positive valid max-age' : 'Strict-Transport-Security absent on HTTPS response', 'Enable HSTS only after confirming HTTPS availability; consider subdomain impact before includeSubDomains.');
    }
    return findings;
  },
};
