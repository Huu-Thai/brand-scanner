import { createHmac, timingSafeEqual } from 'node:crypto';

export interface JwtClaims {
  sub: string;
  exp: number;
  iat?: number;
  nbf?: number;
  [claim: string]: unknown;
}

export class InvalidTokenError extends Error {}

const LEEWAY_S = 30;
const b64json = (part: string): Record<string, unknown> => {
  try {
    return JSON.parse(
      Buffer.from(part, 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
  } catch {
    throw new InvalidTokenError('Malformed token');
  }
};

/**
 * Verifies an HS256 JWT issued by threat-feed (shared secret). Only HS256 is accepted —
 * `alg: none` / RS-HS confusion are rejected — and `exp` is mandatory.
 */
export function verifyHs256(
  token: string,
  secret: string,
  nowMs = Date.now(),
): JwtClaims {
  const parts = token.split('.');
  if (parts.length !== 3) throw new InvalidTokenError('Malformed token');
  const [h, p, sig] = parts;
  if (b64json(h).alg !== 'HS256')
    throw new InvalidTokenError('Unsupported token algorithm');
  const expected = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  const given = Buffer.from(sig, 'base64url');
  if (given.length !== expected.length || !timingSafeEqual(given, expected))
    throw new InvalidTokenError('Invalid token signature');
  const claims = b64json(p) as Partial<JwtClaims>;
  const now = nowMs / 1000;
  if (typeof claims.sub !== 'string' || !claims.sub)
    throw new InvalidTokenError('Token has no subject');
  if (typeof claims.exp !== 'number')
    throw new InvalidTokenError('Token has no expiry');
  if (claims.exp + LEEWAY_S < now) throw new InvalidTokenError('Token expired');
  if (typeof claims.nbf === 'number' && claims.nbf - LEEWAY_S > now)
    throw new InvalidTokenError('Token not yet valid');
  return claims as JwtClaims;
}
