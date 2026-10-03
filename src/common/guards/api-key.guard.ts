import { createHash, timingSafeEqual } from 'node:crypto';
import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import type {
  ApiKeyEntry,
  ApiKeyScope,
  AppConfig,
} from '../../config/configuration.js';
import { UserIdentityService } from '../auth/user-identity.service.js';
import { API_KEY_HEADER } from '../constants/api.constants.js';
import {
  IS_PUBLIC_KEY,
  REQUIRED_SCOPE_KEY,
} from '../decorators/auth.decorators.js';

export interface ApiPrincipal {
  /** API-key name, or `user:<email>` for threat-feed user tokens. */
  name: string;
  /** How the caller authenticated (absent = API key). */
  kind?: 'key' | 'user';
  scope: ApiKeyScope;
  /**
   * Who is acting: the end user asserted by a trusted proxy key (`x-acting-user`, e.g. an
   * analyst signed in to manage-feed), otherwise the key name. Recorded on reviews/status changes.
   */
  actor: string;
}

export const ACTING_USER_HEADER = 'x-acting-user';
const ACTOR_PATTERN = /^[A-Za-z0-9._%+@-]{1,254}$/;

export type AuthenticatedRequest = Request & { principal?: ApiPrincipal };

const SCOPE_RANK: Record<ApiKeyScope, number> = { read: 1, write: 2, admin: 3 };

export function hashApiKey(raw: string): string {
  return createHash('sha256').update(raw, 'utf8').digest('hex');
}

/**
 * Global guard. Keys are configured as SHA-256 hashes (API_KEYS) and compared in
 * constant time; the caller's principal is attached to the request for audit fields
 * such as `reviews.reviewer`.
 */
@Injectable()
export class ApiKeyGuard implements CanActivate {
  private readonly keys: { entry: ApiKeyEntry; digest: Buffer }[];
  private readonly trustedProxies: Set<string>;

  constructor(
    private readonly reflector: Reflector,
    config: ConfigService<AppConfig, true>,
    private readonly identities?: UserIdentityService,
  ) {
    this.keys = config
      .get('apiKeys', { infer: true })
      .map((entry) => ({ entry, digest: Buffer.from(entry.hash, 'hex') }));
    this.trustedProxies = new Set(
      config.get('trustedProxyKeys', { infer: true }),
    );
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const targets = [context.getHandler(), context.getClass()];
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, targets))
      return true;

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const required =
      this.reflector.getAllAndOverride<ApiKeyScope>(
        REQUIRED_SCOPE_KEY,
        targets,
      ) ??
      (['GET', 'HEAD', 'OPTIONS'].includes(request.method) ? 'read' : 'write');

    const raw = request.headers[API_KEY_HEADER];

    console.log('API_KEY_HEADER:', API_KEY_HEADER);
    console.log('API_KEY:', raw);
    const bearer = /^Bearer\s+(\S+)$/i.exec(
      request.headers.authorization ?? '',
    )?.[1];
    if ((typeof raw !== 'string' || raw.length === 0) && bearer) {
      return this.authenticateUser(request, bearer, required);
    }
    if (typeof raw !== 'string' || raw.length === 0) {
      throw new UnauthorizedException('Missing API key');
    }

    const presented = Buffer.from(hashApiKey(raw), 'hex');
    const match = this.keys.find(({ digest }) =>
      timingSafeEqual(digest, presented),
    );

    console.log('API keys: ', this.keys);

     console.log('API key matched:', match);

    if (!match) throw new UnauthorizedException('Invalid API key');


    if (SCOPE_RANK[match.entry.scope] < SCOPE_RANK[required]) {
      throw new ForbiddenException(
        `API key scope "${match.entry.scope}" cannot perform this action`,
      );
    }

    request.principal = {
      name: match.entry.name,
      kind: 'key',
      scope: match.entry.scope,
      actor: this.actorFor(
        match.entry.name,
        request.headers[ACTING_USER_HEADER],
      ),
    };
    return true;
  }

  /** A threat-feed user token: the user acts as themselves; x-acting-user is ignored. */
  private async authenticateUser(
    request: AuthenticatedRequest,
    token: string,
    required: ApiKeyScope,
  ): Promise<boolean> {
    if (!this.identities?.enabled)
      throw new UnauthorizedException('Missing API key');
    const user = await this.identities.resolve(token);
    if (SCOPE_RANK[user.scope] < SCOPE_RANK[required]) {
      throw new ForbiddenException(
        `Your role ("${user.roleKey}") cannot perform this action`,
      );
    }
    request.principal = {
      name: `user:${user.email}`,
      kind: 'user',
      scope: user.scope,
      actor: user.email,
    };
    return true;
  }

  /** Only trusted proxy keys may name the acting user; anyone else is their own key. */
  private actorFor(
    keyName: string,
    header: string | string[] | undefined,
  ): string {
    if (!this.trustedProxies.has(keyName) || typeof header !== 'string')
      return keyName;
    if (!ACTOR_PATTERN.test(header))
      throw new BadRequestException(`Invalid ${ACTING_USER_HEADER} header`);
    return header.toLowerCase();
  }
}
