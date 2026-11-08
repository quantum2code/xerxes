import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type { request, RequestOptions } from 'node:https';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { createGoogleWebRiskProvider } from '../src/modules/threat-detection/blacklist/index.js';
import { createSafeBrowsingFamilyFetch, createWebRiskFamilyFetch } from '../src/modules/threat-detection/blacklist/google-provider-transport.js';
import { createServerPipelineOptions } from '../src/server-options.js';
import { MlPhishingModule } from '../src/modules/threat-detection/ml-phishing/index.js';

const endpoint = 'https://webrisk.googleapis.com/v1/uris:search?uri=https%3A%2F%2Fexample.com';

function fakeRequest(
  status: number,
  body: string,
  inspect: (url: URL, options: RequestOptions) => void = () => {},
  inspectBody: (body: unknown) => void = () => {},
): typeof request {
  return ((url: URL, options: RequestOptions, onResponse: (response: IncomingMessage) => void) => {
    inspect(url, options);
    const req = new EventEmitter() as ClientRequest;
    req.end = ((sentBody?: unknown) => {
      inspectBody(sentBody);
      queueMicrotask(() => {
        const stream = new PassThrough();
        const res = stream as unknown as IncomingMessage;
        res.statusCode = status;
        res.headers = { 'content-type': 'application/json', 'x-test': ['a', 'b'] };
        onResponse(res);
        stream.end(body);
      });
      return req;
    }) as ClientRequest['end'];
    return req;
  }) as typeof request;
}

test('Web Risk transport selects only the configured family while retaining TLS hostname and abort signal', async () => {
  for (const family of [4, 6] as const) {
    const signal = new AbortController().signal;
    const fetch = createWebRiskFamilyFetch(family, fakeRequest(200, '{}', (url, options) => {
      assert.equal(url.hostname, 'webrisk.googleapis.com');
      assert.equal(url.href, endpoint);
      assert.equal(options.family, family);
      assert.equal(options.agent, false);
      assert.notEqual(options.rejectUnauthorized, false);
      assert.equal(options.signal, signal);
      assert.deepEqual(options.headers, { 'x-goog-api-key': 'private-key' });
    }));
    const response = await fetch(endpoint, { method: 'GET', headers: { 'x-goog-api-key': 'private-key' }, signal });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-type'), 'application/json');
    assert.deepEqual(await response.json(), {});
  }
});

test('Safe Browsing family transport sends JSON POST data only to its fixed TLS endpoint', async () => {
  const body = JSON.stringify({ threatInfo: { threatEntries: [{ url: 'https://example.com/' }] } });
  const fetch = createSafeBrowsingFamilyFetch(6, fakeRequest(200, '{}', (url, options) => {
    assert.equal(url.href, 'https://safebrowsing.googleapis.com/v4/threatMatches:find');
    assert.equal(options.method, 'POST');
    assert.equal(options.family, 6);
    assert.notEqual(options.rejectUnauthorized, false);
  }, (sent) => assert.equal(sent, body)));
  const response = await fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find', { method: 'POST', body });
  assert.deepEqual(await response.json(), {});
  await assert.rejects(fetch(endpoint, { method: 'POST', body }), /fixed endpoint/);
  await assert.rejects(fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find', { method: 'GET' }), /fixed endpoint/);
});

test('family transport refuses other hosts, endpoint paths, credentials, bodies, methods, and redirects', async () => {
  let calls = 0;
  const fetch = createWebRiskFamilyFetch(6, fakeRequest(302, '', () => { calls++; }));
  for (const url of ['http://webrisk.googleapis.com/v1/uris:search',
    'https://example.com/v1/uris:search', 'https://webrisk.googleapis.com/other',
    'https://user:secret@webrisk.googleapis.com/v1/uris:search']) {
    await assert.rejects(fetch(url, { method: 'GET' }), /Expected a Google API GET/);
  }
  await assert.rejects(fetch(endpoint, { method: 'POST' }), /Expected a Google API GET/);
  await assert.rejects(fetch(endpoint, { method: 'GET', body: 'bad' }), /Expected a Google API GET/);
  assert.equal(calls, 0);
  await assert.rejects(fetch(endpoint, { method: 'GET' }), /Unexpected Google API HTTP response/);
  assert.equal(calls, 1);
});

test('family transport streams HTTP errors to the shared sanitized provider error handling', async () => {
  const fetch = createWebRiskFamilyFetch(6, fakeRequest(403, 'secret provider payload'));
  const provider = createGoogleWebRiskProvider({ apiKey: 'private-key', fetch });
  await assert.rejects(provider.check('https://example.com/', { signal: new AbortController().signal }), {
    message: 'Google Web Risk authentication or access denied (HTTP 403)',
  });
});

test('family configuration is optional, validates at startup, and does not replace trusted fetch seams', async () => {
  for (const family of ['0', 'auto', 'ipv6', '', ' 6']) {
    assert.throws(() => createServerPipelineOptions(new MlPhishingModule(), {
      GOOGLE_SAFE_BROWSING_ADDRESS_FAMILY: family,
    }), /GOOGLE_SAFE_BROWSING_ADDRESS_FAMILY/);
  }
  for (const family of [4, 6] as const) {
    const options = createServerPipelineOptions(new MlPhishingModule(), {
      GOOGLE_SAFE_BROWSING_API_KEY: 'private-key', GOOGLE_SAFE_BROWSING_ADDRESS_FAMILY: String(family),
    });
    assert.equal(options.blacklist?.timeoutMs, 5000); // No deadline increase to mask routing trouble.
    let calls = 0;
    const provider = createGoogleWebRiskProvider({ apiKey: 'private-key', addressFamily: family,
      fetch: async () => { calls++; return Response.json({}); },
    });
    assert.deepEqual(await provider.check('https://example.com/', { signal: new AbortController().signal }), { matched: false });
    assert.equal(calls, 1);
  }
  assert.throws(() => createGoogleWebRiskProvider({ apiKey: 'private-key', addressFamily: 0 as 4 }), /addressFamily/);
});
