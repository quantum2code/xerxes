import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { Ajv2020 } from 'ajv/dist/2020.js';
import formats from 'ajv-formats';
import { WebSecurityScanner, loadConfig } from '../src/modules/web-security/index.js';
import { normalize, countSeverities } from '../src/modules/web-security/reporting/normalize.js';
import { severities, type FindingInput } from '../src/modules/web-security/types.js';

const schema = JSON.parse(await readFile(new URL('../docs/web-security-scan.schema.json', import.meta.url), 'utf8'));
const ajv = new Ajv2020({ allErrors: true });
// CommonJS package exposes the callable format plugin under default when using NodeNext.
formats.default(ajv);
const validate = ajv.compile(schema);
test('real completed and blocked results satisfy the published JSON schema', async () => {
  const scanner = new WebSecurityScanner(loadConfig({ WEB_SECURITY_REQUIRE_PASSIVE_AUTH: 'false' }), {
    transport: async (url) => ({ url: url.href, status: 200, headers: { 'content-type': 'text/html' }, body: '<form action="http://example.com/login"></form>' }),
  });
  for (const input of [{ url: 'https://example.com' }, { url: 'file:///etc/passwd' }, null]) {
    const result = await scanner.scan(input);
    assert.equal(validate(result), true, JSON.stringify(validate.errors));
  }
});
test('every severity and confidence is preserved and counted without computing a verdict', () => {
  const base: FindingInput = { checkId: 'test', title: 'test', description: 'test', severity: 'low', confidence: 'high', affectedUrl: 'https://example.com/', evidence: [{ location: 'response', observation: 'test' }], remediation: 'fix' };
  const findings = severities.flatMap((severity) => (['low', 'medium', 'high'] as const).map((confidence) => normalize({ ...base, severity, confidence })));
  assert.deepEqual(Object.values(countSeverities(findings)), [3, 3, 3, 3, 3]);
  assert.ok(findings.every((f) => !('score' in f) && !('verdict' in f)));
  for (const finding of findings) assert.equal(ajv.getSchema('urn:xerxes:web-security-scan:1.0#/$defs/finding')?.(finding), true);
});
