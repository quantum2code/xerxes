import type { Check } from '../types.js';
import { header, isHtml, observation } from './helpers.js';

export const informationDisclosure: Check = {
  id: 'information-disclosure',
  run(page) {
    const findings = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'].flatMap((name) => {
      const value = header(page, name);
      if (!value || (name === 'server' && !/\d+\.\d+/.test(value))) return [];
      return [observation(page, this.id, 'Server technology information disclosed',
        'A response header discloses implementation details; this does not establish a vulnerable version.',
        `${name} header contains technology information; value omitted`, 'informational', ['CWE-200'], 'Remove unnecessary technology/version response headers.')];
    });
    const signatures = [
      ['PHP error', /(?:Fatal error|Warning):[\s\S]{0,160}\bon line \d+/i],
      ['Python traceback', /Traceback \(most recent call last\):/],
      ['Java stack trace', /\bat [\w.$]{1,128}\([^\r\n)]{0,256}\.java:\d{1,10}\)/],
      ['Node.js stack trace', /\bat (?:[\w.$]{1,128} )?\(?[^\r\n]{0,256}\.(?:js|ts):\d{1,10}:\d{1,10}\)?/],
      ['ASP.NET debug error', /Server Error in ['"][^'"\r\n]+['"] Application/],
    ] as const;
    for (const [name, pattern] of signatures) if (pattern.test(page.body)) findings.push(observation(page, this.id,
      'Debug or error details exposed', 'A recognizable error/debug signature occurs in a publicly returned response. Example code may cause a false positive.',
      `${name} signature matched; paths and stack content omitted`, 'low', ['CWE-209'], 'Disable production debug pages and return generic errors; log details only on the server.'));
    if (isHtml(page) && /<!--(?:(?!-->)[\s\S]){0,2000}\b(?:TODO|FIXME|DEBUG)\b/i.test(page.body)) findings.push(observation(page, this.id,
      'Development comment exposed', 'A development marker is present in an HTML comment; sensitive content has not necessarily been disclosed.',
      'TODO/FIXME/DEBUG marker inside HTML comment; comment text omitted', 'informational', ['CWE-615'], 'Remove unnecessary internal development comments from production output.'));
    return findings;
  },
};
export const directoryListing: Check = {
  id: 'directory-listing',
  run(page) {
    if (!isHtml(page) || !/<(?:title|h1)[^>]{0,512}>\s*(?:Index of|Directory listing for)\s*\//i.test(page.body) ||
      !/(?:Parent Directory|href=["']\.\.\/|Last modified|<hr\s*\/?\s*>)/i.test(page.body)) return [];
    return [{ ...observation(page, this.id, 'Directory listing indicators',
      'Multiple directory-index indicators were observed. The exposed file sensitivity is not established.',
      'Index heading and directory-navigation/table signature matched', 'low', ['CWE-548'], 'Disable automatic directory indexes unless explicitly required.'), confidence: 'medium' as const }];
  },
};
export const sensitiveExposure: Check = {
  id: 'sensitive-exposure',
  run(page) {
    const signatures = [
      ['Private key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
      ['AWS access key identifier', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
      ['Environment credential assignment', /(?:^|\n)[ \t]{0,64}(?:DB_PASSWORD|DATABASE_PASSWORD|AWS_SECRET_ACCESS_KEY|STRIPE_SECRET_KEY)[ \t]{0,64}=[ \t]{0,64}[^\s]{4,}/],
    ] as const;
    return signatures.filter(([, regex]) => regex.test(page.body)).map(([kind]) => ({ ...observation(page, this.id,
      'Potential sensitive information in public response', 'A high-specificity secret-format marker was found. Validity and permissions were not tested; sample keys can produce false positives.',
      `${kind} marker matched; all secret material omitted`, 'high', ['CWE-200'], 'Remove exposed material, investigate access, and revoke/rotate any real credentials.'), confidence: 'medium' as const }));
  },
};
