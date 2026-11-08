import type { Check } from '../types.js';
import { baseUrl, elements, observation } from './helpers.js';

export const mixedContent: Check = {
  id: 'mixed-content',
  run(page) {
    if (new URL(page.url).protocol !== 'https:') return [];
    const base = baseUrl(page);
    return elements(page).flatMap(({ tag, attrs }) => {
      if (!['script', 'iframe', 'img', 'link', 'audio', 'video', 'source', 'object', 'embed'].includes(tag)) return [];
      if (tag === 'link' && !/stylesheet|preload|modulepreload|icon/i.test(attrs.rel ?? '')) return [];
      const refs = [attrs.src, attrs.href, attrs.data, attrs.poster, ...(attrs.srcset ?? '').split(',').map((s) => s.trim().split(/\s+/)[0])];
      return refs.filter((ref): ref is string => !!ref).flatMap((ref) => {
        let target: URL;
        try { target = new URL(ref, base); } catch { return []; }
        if (target.protocol !== 'http:') return [];
        return [observation(page, this.id, 'HTTP resource referenced by HTTPS document',
          'The document references an insecure resource. Browsers or CSP may block or upgrade it; execution was not tested.',
          `${tag} references ${target.href}`, ['script', 'iframe', 'object', 'embed', 'link'].includes(tag) ? 'medium' : 'low', ['CWE-319'],
          'Serve all resources over HTTPS; remove insecure absolute URLs and use an enforcing CSP.')];
      });
    });
  },
};
