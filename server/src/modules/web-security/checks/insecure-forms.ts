import type { Check } from '../types.js';
import { baseUrl, elements, observation } from './helpers.js';

export const insecureForms: Check = {
  id: 'insecure-forms',
  run(page) {
    const base = baseUrl(page);
    const nodes = elements(page);
    return nodes.filter((e) => e.tag === 'form').flatMap(({ attrs }, index) => {
      const controls = nodes.filter((e) => e.attrs.form ? e.attrs.form === attrs.id : e.formOwner === attrs);
      const actions = [{ action: attrs.action || page.url, method: attrs.method ?? 'get' },
        ...controls.filter((e) => ['button', 'input'].includes(e.tag) && (e.attrs.formaction || e.attrs.formmethod)).map((e) => ({ action: e.attrs.formaction || attrs.action || page.url, method: e.attrs.formmethod ?? attrs.method ?? 'get' }))];
      return actions.flatMap((submission) => {
        let action: URL;
        try { action = new URL(submission.action, base); } catch { return []; }
        const findings = action.protocol === 'http:' ? [observation(page, this.id, 'Form submits over unencrypted HTTP',
          'The declared form action uses HTTP. No form was submitted; script handlers or browser upgrades may alter behavior.',
          `form #${index + 1}, method ${submission.method.toUpperCase()}, action ${action.href}`, 'medium', ['CWE-319'],
          'Serve forms and submission endpoints over HTTPS; do not rely on redirects to protect submitted data.')] : [];
        if (submission.method.toLowerCase() === 'get' && controls.some((e) => e.tag === 'input' && e.attrs.type?.toLowerCase() === 'password' && !('disabled' in e.attrs) && !!e.attrs.name)) {
          findings.push(observation(page, this.id, 'Password form uses GET submission',
            'A named, enabled password control belongs to a form declared to submit by GET. Values can enter URLs, history, and logs. No form was submitted.',
            `form #${index + 1}: GET submission with password input; input names and values omitted`, 'medium', ['CWE-598'],
            'Submit sensitive form data using POST over HTTPS and avoid logging request bodies.'));
        }
        return findings;
      });
    });
  },
};
