import { Injectable } from '@nestjs/common';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import type { AuthenticatedRequest } from './api-key.guard.js';

/**
 * Rate limits per API key (falls back to client IP for public routes). Keying by IP would put
 * every analyst behind the manage-feed gateway into one bucket — and let one noisy key starve others.
 * Runs after ApiKeyGuard, so `req.principal` is set for authenticated routes.
 */
@Injectable()
export class ApiKeyThrottlerGuard extends ThrottlerGuard {
  protected getTracker(req: Record<string, unknown>): Promise<string> {
    const principal = (req as unknown as AuthenticatedRequest).principal;
    return Promise.resolve(
      principal ? `key:${principal.name}` : `ip:${String(req.ip ?? 'unknown')}`,
    );
  }
}

/**
 * Stricter per-route budget for endpoints that start background work or stream large results.
 * Counters are per key *and* per route; THROTTLE_EXPENSIVE_LIMIT (default 10) per THROTTLE_TTL_MS.
 */
export const ExpensiveThrottle = () =>
  Throttle({
    default: {
      limit: () => Number(process.env.THROTTLE_EXPENSIVE_LIMIT ?? 10),
      ttl: () => Number(process.env.THROTTLE_TTL_MS ?? 60_000),
    },
  });
