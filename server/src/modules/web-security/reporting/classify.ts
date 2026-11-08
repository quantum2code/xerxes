/** OWASP 2021 mapping only where this limited mapping is defensible. No CVSS inference. */
export function owaspForCwe(cwe: string): string[] {
  if (['CWE-79', 'CWE-89', 'CWE-78'].includes(cwe)) return ['A03:2021'];
  if (['CWE-942', 'CWE-16', 'CWE-209', 'CWE-548'].includes(cwe)) return ['A05:2021'];
  if (['CWE-319', 'CWE-614'].includes(cwe)) return ['A02:2021'];
  if (cwe === 'CWE-918') return ['A10:2021'];
  return [];
}
