/**
 * VulnHunter AI - Sensitive Data Redactor
 * Redacts tokens, credentials, session cookies, and sensitive headers/payloads.
 */

const SENSITIVE_HEADER_KEYS = [
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'api-key',
  'x-auth-token',
  'session',
  'token',
  'x-csrf-token',
  'proxy-authorization'
];

const SECRET_PATTERNS = [
  /([a-zA-Z0-9_\-\.]{20,})\b/g, // generic long hash/token
  /(ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})/g, // JWT
  /(AIza[0-9A-Za-z-_]{35})/g, // Google API key
  /(ghp_[a-zA-Z0-9]{36})/g, // GitHub PAT
  /(sk-[a-zA-Z0-9]{40,})/g, // generic API secret
  /([Pp]assword|[Pp]asswd|[Ss]ecret|[Tt]oken|[Aa]pi[kK]ey)\s*[:=]\s*["']?([^"',\s&]+)/g
];

export function redactHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const sanitized: Record<string, string> = {};

  for (const [key, rawVal] of Object.entries(headers)) {
    if (!rawVal) continue;
    const lowerKey = key.toLowerCase();
    const strVal = Array.isArray(rawVal) ? rawVal.join('; ') : String(rawVal);

    if (SENSITIVE_HEADER_KEYS.includes(lowerKey)) {
      if (lowerKey === 'authorization') {
        const parts = strVal.split(' ');
        const scheme = parts[0] || 'Bearer';
        sanitized[key] = `${scheme} [REDACTED_TOKEN_LEN_${strVal.length}]`;
      } else if (lowerKey === 'cookie' || lowerKey === 'set-cookie') {
        sanitized[key] = strVal.replace(/([^=;\s]+)=([^;]+)/g, (_match, name) => {
          return `${name}=[REDACTED]`;
        });
      } else {
        sanitized[key] = `[REDACTED_${key.toUpperCase()}]`;
      }
    } else {
      sanitized[key] = sanitizeString(strVal);
    }
  }

  return sanitized;
}

export function sanitizeString(text: string): string {
  if (!text) return '';
  let result = text;

  // Redact potential JWTs
  result = result.replace(/(ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})/g, '[REDACTED_JWT]');

  // Redact password or secret key queries/params
  result = result.replace(/([?&](?:password|token|api_key|secret|auth|access_token|key)=)([^&]+)/gi, '$1[REDACTED]');

  // Redact password JSON fields
  result = result.replace(/("(?:password|secret|token|apiKey|api_key|privateKey)"\s*:\s*")([^"]+)(")/gi, '$1[REDACTED]$3');

  return result;
}

export function redactBody(body: string | object | null | undefined, maxLen = 4096): string {
  if (!body) return '';
  const str = typeof body === 'object' ? JSON.stringify(body, null, 2) : String(body);
  const truncated = str.length > maxLen ? str.slice(0, maxLen) + `\n... [TRUNCATED - EXCEEDED ${maxLen} BYTES]` : str;
  return sanitizeString(truncated);
}
