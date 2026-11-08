import assert from 'node:assert/strict';
import test from 'node:test';
import { createGoogleJsonClient } from '../src/modules/threat-detection/blacklist/google-provider.js';

test('shared Google client snapshots credentials and transport without mutating caller headers', async () => {
  let calls = 0;
  const options = { apiKey: 'server-key', addressFamily: 6 as const, fetch: (async (_endpoint, init) => {
    calls++;
    const headers = new Headers(init?.headers);
    assert.equal(headers.get('x-goog-api-key'), 'server-key');
    assert.equal(headers.get('accept'), 'application/json');
    assert.equal(headers.get('content-type'), 'application/json');
    assert.equal(init?.redirect, 'error');
    return Response.json({});
  }) as typeof globalThis.fetch };
  const requestJson = createGoogleJsonClient('Test Google API', options, () => {
    throw new Error('An injected fetch must take precedence over native family selection');
  });
  options.apiKey = 'changed';
  options.fetch = async () => { throw new Error('Must not use mutated configuration'); };
  const headers = new Headers({ 'x-goog-api-key': 'untrusted-key', accept: 'text/html', 'content-type': 'application/json' });
  assert.deepEqual(await requestJson('https://example.invalid/', { method: 'POST', headers }), {});
  assert.equal(headers.get('x-goog-api-key'), 'untrusted-key');
  assert.equal(headers.get('accept'), 'text/html');
  assert.equal(calls, 1);
});
