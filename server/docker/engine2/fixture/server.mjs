import http from 'node:http';

// Intentionally vulnerable, dependency-free acceptance fixture, NOT production application code.
// Raw reflection and absent framing/CSP headers let real ZAP rules produce reproducible findings.
http.createServer({ maxHeaderSize: 16384, requestTimeout: 5000 }, (req, res) => {
  const url = new URL(req.url, 'http://xerxes-engine2-fixture:8080');
  if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405); res.end(); return; }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  if (url.pathname === '/app') {
    res.end('<!doctype html><html><head><title>Isolated Engine2 fixture</title></head><body><a href="/app/search?q=hello">Search</a><a href="/app/about">About</a></body></html>');
  } else if (url.pathname === '/app/search') {
    res.end(`<!doctype html><html><head><title>Search fixture</title></head><body><p>Search: ${url.searchParams.get('q') ?? ''}</p></body></html>`);
  } else if (url.pathname === '/app/about') {
    res.end('<!doctype html><html><head><title>About</title></head><body>Isolated, anonymous ZAP acceptance fixture.</body></html>');
  } else { res.writeHead(404); res.end('Not found'); }
}).listen(8080, '0.0.0.0');
