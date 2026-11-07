export function redact(value: string): string {
  return value
    .replace(/(?:set-cookie|cookie|authorization)\s*:[^\r\n]*/gi, '[REDACTED SENSITIVE HEADER]')
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g, '[REDACTED PRIVATE KEY]')
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[REDACTED ACCESS KEY]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED JWT]')
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9+/_=.~-]+/gi, '$1 [REDACTED]')
    .replace(/((?:password|passwd|secret|token|api[_-]?key|authorization|cookie|session(?:id)?)["']?\s*[=:]\s*["']?)[^\s"'<>&;,]+/gi, '$1[REDACTED]')
    .replace(/https?:\/\/[^\s<>"']+/gi, (raw) => safeUrl(raw));
}
export function safeUrl(raw: string): string {
  try {
    const url = new URL(raw);
    url.username = ''; url.password = ''; url.hash = '';
    for (const key of new Set(url.searchParams.keys())) url.searchParams.set(key, '[REDACTED]');
    const segments = url.pathname.split('/');
    url.pathname = segments.map((part, index) => part.length > 24 || /@|%40/i.test(part) ||
      /^(?:reset|reset-password|token|secret|session|api-key)$/i.test(segments[index - 1] ?? '') ? '[REDACTED]' : part).join('/');
    return url.href;
  } catch { return '[invalid URL]'; }
}
