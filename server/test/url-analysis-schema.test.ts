import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { UrlAnalyzer } from '../src/modules/url-analysis/index.js';

const schema = JSON.parse(await readFile(new URL('../docs/url-analysis.schema.json', import.meta.url), 'utf8'));
const validate = new Ajv2020({ allErrors: true }).compile(schema);
test('all public URL result states conform to the documented JSON contract', async () => {
  const analyzer = new UrlAnalyzer(undefined, { query: async (type) => type === 'A' ? [{ address: '8.8.8.8', ttl: 30 }] : [],
    transport: async (url) => { if (url.hostname === 'failed.example') throw new Error('secret'); return { statusCode: 200, headers: { 'content-type': 'text/html' } }; } });
  for (const input of [null, { url: 'file:///etc/passwd' }, { url: 'http://127.0.0.1' }, { url: 'http://example.com:0' }, { url: 'https://example.com?q=secret#fragment' }, { url: 'https://bücher.de/' }, { url: 'https://failed.example' }, { url: 'http://8.8.8.8' }]) {
    const result = await analyzer.analyze(input);
    assert.equal(validate(result), true, JSON.stringify(validate.errors));
  }
});
