import { createHash } from 'node:crypto';
import {
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Redis } from 'ioredis';
import type { ApiKeyScope, AppConfig } from '../../config/configuration.js';
import { REDIS_CLIENT } from '../../redis/redis.module.js';
import { InvalidTokenError, verifyHs256 } from './jwt.js';

export interface UserIdentity {
  userId: string;
  email: string;
  roleKey: string;
  scope: ApiKeyScope;
}

interface Rule {
  key: string;
  method: string;
  path: string;
}

/** Same matching as threat-feed's PermissionsGuard (and manage-feed's lib/permissions). */
export function can(rules: Rule[], method: string, path: string): boolean {
  const required = method === 'GET' || method === 'HEAD' ? 'read' : 'write';
  return rules.some((r) => {
    const pathOk =
      r.path === '*' ||
      r.path === path ||
      (r.path.endsWith('/*') &&
        (path === r.path.slice(0, -2) || path.startsWith(r.path.slice(0, -1))));
    return (
      (r.key === '*' || r.key === required) &&
      (r.method === '*' || r.method === method) &&
      pathOk
    );
  });
}

/**
 * Maps a threat-feed role onto fuzzer-scanner scopes — the same contract the manage-feed gateway
 * uses: full access → admin; may create indicators → write; may read indicators → read.
 */
export function scopeFor(rules: Rule[]): ApiKeyScope | null {
  if (rules.some((r) => r.key === '*' && r.method === '*' && r.path === '*'))
    return 'admin';
  if (can(rules, 'POST', '/feeds')) return 'write';
  if (can(rules, 'GET', '/feeds')) return 'read';
  return null;
}

/**
 * Resolves a threat-feed user token: signature/expiry checked locally (shared HS256 secret),
 * identity + role permissions from threat-feed `GET /auth/me` (so deactivated users and role
 * changes take effect), cached per token for AUTH_IDENTITY_CACHE_MS (never past the token's expiry).
 */
@Injectable()
export class UserIdentityService {
  private readonly logger = new Logger(UserIdentityService.name);

  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    @Inject(REDIS_CLIENT) private readonly redis: Redis,
  ) {}

  get enabled(): boolean {
    return !!this.config.get('auth', { infer: true }).jwtSecret;
  }

  async resolve(token: string): Promise<UserIdentity> {
    const { jwtSecret, identityCacheMs } = this.config.get('auth', {
      infer: true,
    });
    if (!jwtSecret)
      throw new UnauthorizedException(
        'Bearer tokens are not accepted (AUTH_JWT_SECRET not set)',
      );
    let claims;
    try {
      claims = verifyHs256(token, jwtSecret);
    } catch (e) {
      throw new UnauthorizedException(
        e instanceof InvalidTokenError ? e.message : 'Invalid token',
      );
    }

    const key = `auth:me:${createHash('sha256').update(token).digest('hex')}`;
    const cached = await this.redis.get(key).catch(() => null);
    if (cached) return JSON.parse(cached) as UserIdentity;

    const me = await this.fetchMe(token);
    const scope = scopeFor(me.permissions);
    if (!scope)
      throw new ForbiddenException(
        'Your role has no access to look-alike monitoring',
      );
    const identity: UserIdentity = {
      userId: me.id,
      email: me.email.toLowerCase(),
      roleKey: me.role.key,
      scope,
    };
    const ttl = Math.min(identityCacheMs, claims.exp * 1000 - Date.now());
    if (ttl > 0)
      await this.redis
        .set(key, JSON.stringify(identity), 'PX', Math.floor(ttl))
        .catch(() => undefined);
    return identity;
  }

  private async fetchMe(token: string): Promise<{
    id: string;
    email: string;
    role: { key: string };
    permissions: Rule[];
  }> {
    const { url, timeoutMs } = this.config.get('threatFeed', { infer: true });
    let res: Response;
    try {
      res = await fetch(`${url}/auth/me`, {
        headers: {
          authorization: `Bearer ${token}`,
          accept: 'application/json',
        },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      this.logger.warn(
        `threat-feed /auth/me unreachable: ${(e as Error).message}`,
      );
      throw new ServiceUnavailableException('Identity provider unavailable');
    }
    if (res.status === 401)
      throw new UnauthorizedException('Session is no longer valid');
    if (!res.ok) {
      this.logger.warn(`threat-feed /auth/me → HTTP ${res.status}`);
      throw new ServiceUnavailableException('Identity provider unavailable');
    }
    return (await res.json()) as {
      id: string;
      email: string;
      role: { key: string };
      permissions: Rule[];
    };
  }
}
