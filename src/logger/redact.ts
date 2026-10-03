/** Keys whose values must never reach a log sink, matched case-insensitively at any depth. */
const SENSITIVE_KEY =
  /pass(word)?|secret|authorization|cookie|api[-_]?key|token|credential|database_url|connection[-_]?string/i;

export const REDACTED = '[REDACTED]';

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY.test(key);
}

/** Masks credentials embedded in strings: URL userinfo and bearer tokens. */
export function redactString(value: string): string {
  return value
    .replace(
      /(\b[a-z][a-z0-9+.-]*:\/\/[^:/\s@]*:)[^@\s/]+@/gi,
      `$1${REDACTED}@`,
    )
    .replace(/(bearer\s+)[a-z0-9._~+/=-]+/gi, `$1${REDACTED}`);
}

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 8 || value === null || value === undefined) return value;
  if (typeof value === 'string') return redactString(value);
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value instanceof Error) return value;
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
      out[key] = isSensitiveKey(key) ? REDACTED : redact(v, depth + 1);
    }
    return out;
  }
  return value;
}
