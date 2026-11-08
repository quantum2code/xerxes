import type { Check } from '../types.js';
import { observation } from './helpers.js';

export const cookies: Check = {
  id: 'cookies',
  run(page) {
    const raw = Object.entries(page.headers).find(([key]) => key.toLowerCase() === 'set-cookie')?.[1];
    return (Array.isArray(raw) ? raw : raw ? [raw] : []).flatMap((cookie, index) => {
      const parts = cookie.split(';').slice(1).map((v) => v.trim().toLowerCase());
      const attrs = new Set(parts.map((p) => p.split('=')[0]));
      const sameSite = parts.find((p) => p.startsWith('samesite='))?.slice(9);
      const missing = ['secure', 'httponly'].filter((attr) => !attrs.has(attr));
      if (!sameSite || !['strict', 'lax', 'none'].includes(sameSite)) missing.push('valid SameSite');
      const findings = missing.length ? [observation(page, this.id, 'Cookie hardening attributes missing',
        'Cookie purpose is unknown: some cookies intentionally allow script access. Browser SameSite defaults may mitigate omission.',
        `Set-Cookie #${index + 1}: missing ${missing.join(', ')}; cookie name/value omitted`, 'low',
        [...(!attrs.has('secure') ? ['CWE-614'] : []), ...(!attrs.has('httponly') ? ['CWE-1004'] : []), ...(!sameSite || !['strict', 'lax', 'none'].includes(sameSite) ? ['CWE-1275'] : [])],
        'Use Secure for HTTPS cookies, HttpOnly for session cookies, and an explicit SameSite policy appropriate to the application.')] : [];
      if (sameSite === 'none' && !attrs.has('secure')) findings.push(observation(page, this.id, 'SameSite=None cookie lacks Secure',
        'Modern browsers reject this cookie configuration; this does not demonstrate session compromise.',
        `Set-Cookie #${index + 1}: SameSite=None without Secure; name/value omitted`, 'low', ['CWE-614'], 'Add Secure when using SameSite=None.'));
      return findings;
    });
  },
};
