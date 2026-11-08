import type { CertificateFinding } from './evaluate.js';

/** The three Engine 3 areas, so a dashboard can group findings. */
export type FindingCategory = NonNullable<CertificateFinding['category']>;

const BY_ID: Record<string, FindingCategory> = {
  'cert.self_signed': 'chain',
  'cert.untrusted_chain': 'chain',
  'cert.weak_key': 'crypto',
};

/** Findings that already carry a category keep it. Everything else defaults to validity. */
export function categorize<T extends CertificateFinding>(finding: T): T & { category: FindingCategory } {
  return { ...finding, category: finding.category ?? BY_ID[finding.id] ?? 'validity' };
}