import { z } from 'zod';
import { classifyAddress } from '../../../shared/network/policy.js';
import { AnalysisFailure } from '../errors.js';
import type { DnsResult, RecordType, UrlAnalysisConfig } from '../types.js';

const hostname = z.string().min(1).max(253).regex(/^[a-z0-9_.-]+\.?$/i);
const address = z.object({ address: z.ipv4(), ttl: z.number().int().nonnegative() });
const address6 = z.object({ address: z.ipv6(), ttl: z.number().int().nonnegative() });
const validators = {
  A: z.array(address), AAAA: z.array(address6), CNAME: z.array(hostname),
  MX: z.array(z.object({ exchange: z.union([hostname, z.literal('')]), priority: z.number().int().min(0).max(65535) })),
  NS: z.array(hostname), TXT: z.array(z.array(z.string())),
};
export function applyRecords(result: DnsResult, type: RecordType, raw: unknown[], config: UrlAnalysisConfig): boolean {
  const parsed = validators[type].safeParse(raw);
  if (!parsed.success) throw new AnalysisFailure('INVALID_DNS_RESPONSE', 'Resolver returned malformed record data');
  const selected = parsed.data.slice(0, config.maxDnsRecords);
  switch (type) {
    case 'A': case 'AAAA': {
      const values = (selected as { address: string; ttl: number }[]).map((r) => ({ ...r, network: classifyAddress(r.address) }));
      if (type === 'A') result.a = values; else result.aaaa = values;
      break;
    }
    case 'CNAME': result.cname = selected as string[]; break;
    case 'NS': result.ns = selected as string[]; break;
    case 'MX': result.mx = selected as DnsResult['mx']; break;
    case 'TXT': {
      let bytes = 0;
      result.txt = [];
      for (const segments of selected as string[][]) {
        const byteLength = segments.reduce((n, segment) => n + Buffer.byteLength(segment), 0);
        bytes += byteLength;
        if (bytes > config.maxDnsTextBytes) return true;
        const text = segments.join('');
        const kind = /^v=spf1\b/i.test(text) ? 'spf' : /^v=DMARC1\b/i.test(text) ? 'dmarc' : /\bv=DKIM1\b/i.test(text) ? 'dkim' : /verification|validation/i.test(text) ? 'verification' : 'other';
        // TXT frequently contains verification/authorization capabilities. Never expose raw strings.
        result.txt.push({ segments: ['[REDACTED TXT]'], byteLength, kind });
      }
    }
  }
  return parsed.data.length > config.maxDnsRecords;
}
