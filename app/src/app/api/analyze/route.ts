export const runtime = 'nodejs';

const headers = { 'Cache-Control': 'no-store' };

export async function POST(request: Request) {
  if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
    return Response.json({ error: { message: 'Use Content-Type: application/json.' } }, { status: 415, headers });
  }
  let body: unknown;
  try {
    // Bound the incoming stream, not just the declared Content-Length.
    const reader = request.body?.getReader();
    if (!reader) throw new Error('Missing body');
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 16384) {
        await reader.cancel();
        return Response.json({ error: { message: 'Request is too large.' } }, { status: 413, headers });
      }
      chunks.push(value);
    }
    body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return Response.json({ error: { message: 'Provide a valid JSON request.' } }, { status: 400, headers });
  }
  if (!body || typeof body !== 'object' || !('url' in body) || typeof body.url !== 'string') {
    return Response.json({ error: { message: 'Provide a URL to analyze.' } }, { status: 400, headers });
  }
  try {
    const upstream = await fetch(new URL('/api/analyze', process.env.ANALYSIS_API_URL || 'http://127.0.0.1:3000'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: body.url }),
      cache: 'no-store',
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(120_000)]),
    });
    return Response.json(await upstream.json(), { status: upstream.status, headers });
  } catch {
    return Response.json({ error: { message: 'The analysis server is unavailable or took too long. Please try again.' } }, { status: 502, headers });
  }
}
