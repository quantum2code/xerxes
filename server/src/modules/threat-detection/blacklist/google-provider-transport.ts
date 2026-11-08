import { request } from 'node:https';
import { Readable } from 'node:stream';

/** Optional Google API-only DNS family selection; never changes global fetch/DNS or redirect safety. */
export function createWebRiskFamilyFetch(
  family: 4 | 6,
  requestImpl: typeof request = request,
): typeof globalThis.fetch {
  return createGoogleFamilyFetch(family, 'https://webrisk.googleapis.com', '/v1/uris:search', 'GET', requestImpl);
}

export function createSafeBrowsingFamilyFetch(family: 4 | 6, requestImpl: typeof request = request): typeof globalThis.fetch {
  return createGoogleFamilyFetch(family, 'https://safebrowsing.googleapis.com', '/v4/threatMatches:find', 'POST', requestImpl);
}

function createGoogleFamilyFetch(
  family: 4 | 6, origin: string, path: string, method: 'GET' | 'POST', requestImpl: typeof request,
): typeof globalThis.fetch {
  return async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    // This adapter is not a general-purpose fetch or a transport for submitted URLs.
    if (url.origin !== origin || url.pathname !== path || url.username || url.password
      || init?.method !== method || (method === 'GET' ? init.body !== undefined : typeof init.body !== 'string')) {
      throw new TypeError(`Expected a Google API ${method} request to its fixed endpoint`);
    }
    return new Promise<Response>((resolve, reject) => {
      const headers = Object.fromEntries(new Headers(init.headers));
      const req = requestImpl(url, {
        method, headers, family, agent: false,
        signal: init.signal ?? undefined,
      }, (res) => {
        // Do not follow redirects or forward the API key to another endpoint.
        if (res.statusCode === undefined || (res.statusCode >= 300 && res.statusCode < 400)) {
          res.destroy();
          reject(new Error('Unexpected Google API HTTP response'));
          return;
        }
        if (res.statusCode >= 400) {
          // Error bodies are deliberately discarded; only the status enters diagnostics.
          res.destroy();
          resolve(new Response(null, { status: res.statusCode }));
          return;
        }
        try {
          const responseHeaders = new Headers();
          for (const [name, value] of Object.entries(res.headers)) {
            if (Array.isArray(value)) for (const item of value) responseHeaders.append(name, item);
            else if (value !== undefined) responseHeaders.set(name, value);
          }
          const noBody = res.statusCode === 204 || res.statusCode === 205;
          if (noBody) res.resume();
          resolve(new Response(noBody ? null : Readable.toWeb(res) as ReadableStream<Uint8Array>, {
            status: res.statusCode, headers: responseHeaders,
          }));
        } catch (error) {
          res.destroy();
          reject(error);
        }
      });
      req.once('error', reject);
      req.end(init.body as string | undefined);
    });
  };
}
