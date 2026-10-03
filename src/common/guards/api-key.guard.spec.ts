import { createHmac } from 'node:crypto';
import {
  ForbiddenException,
  UnauthorizedException,
  type ExecutionContext,
} from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import type { AppConfig } from '../../config/configuration.js';
import { verifyHs256 } from '../auth/jwt.js';
import {
  can,
  scopeFor,
  UserIdentityService,
} from '../auth/user-identity.service.js';
import {
  IS_PUBLIC_KEY,
  REQUIRED_SCOPE_KEY,
} from '../decorators/auth.decorators.js';
import {
  ApiKeyGuard,
  hashApiKey,
  type AuthenticatedRequest,
} from './api-key.guard.js';

const READ_KEY = 'fsk_read_secret';
const WRITE_KEY = 'fsk_write_secret';
const SECRET = 'threat-feed-jwt-secret-0123456789';

function jwt(
  claims: Record<string, unknown>,
  alg = 'HS256',
  secret = SECRET,
): string {
  const h = Buffer.from(JSON.stringify({ alg, typ: 'JWT' })).toString(
    'base64url',
  );
  const p = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const sig = createHmac('sha256', secret)
    .update(`${h}.${p}`)
    .digest('base64url');
  return `${h}.${p}.${sig}`;
}
const exp = () => Math.floor(Date.now() / 1000) + 900;

function setup(
  metadata: Record<string, unknown> = {},
  identities?: Partial<UserIdentityService>,
) {
  const reflector = new Reflector();
  vi.spyOn(reflector, 'getAllAndOverride').mockImplementation(
    (key) => metadata[key as string],
  );
  const config = {
    get: (key: string) =>
      key === 'trustedProxyKeys'
        ? ['writer']
        : [
            { name: 'reader', scope: 'read', hash: hashApiKey(READ_KEY) },
            { name: 'writer', scope: 'write', hash: hashApiKey(WRITE_KEY) },
          ],
  } as unknown as ConfigService<AppConfig, true>;
  return new ApiKeyGuard(
    reflector,
    config,
    identities as UserIdentityService | undefined,
  );
}

function ctx(
  method: string,
  key?: string,
  actingUser?: string,
  bearer?: string,
) {
  const headers: Record<string, string> = key ? { 'x-api-key': key } : {};
  if (actingUser) headers['x-acting-user'] = actingUser;
  if (bearer) headers.authorization = `Bearer ${bearer}`;
  const request = { method, headers } as unknown as AuthenticatedRequest;
  const context = {
    getHandler: () => undefined,
    getClass: () => undefined,
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
  return { context, request };
}

describe('ApiKeyGuard — API keys', () => {
  it('lets @Public routes through without a key', async () => {
    await expect(
      setup({ [IS_PUBLIC_KEY]: true }).canActivate(ctx('GET').context),
    ).resolves.toBe(true);
  });

  it('rejects a missing or unknown key with 401', async () => {
    await expect(
      setup().canActivate(ctx('GET').context),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(
      setup().canActivate(ctx('GET', 'nope').context),
    ).rejects.toThrow('Invalid API key');
  });

  it('accepts a valid key and attaches the principal', async () => {
    const { context, request } = ctx('GET', READ_KEY);
    await expect(setup().canActivate(context)).resolves.toBe(true);
    expect(request.principal).toEqual({
      name: 'reader',
      kind: 'key',
      scope: 'read',
      actor: 'reader',
    });
  });

  it('requires write scope for mutating methods and honours @RequireScope', async () => {
    await expect(
      setup().canActivate(ctx('POST', READ_KEY).context),
    ).rejects.toBeInstanceOf(ForbiddenException);
    await expect(
      setup().canActivate(ctx('DELETE', WRITE_KEY).context),
    ).resolves.toBe(true);
    await expect(
      setup({ [REQUIRED_SCOPE_KEY]: 'admin' }).canActivate(
        ctx('GET', WRITE_KEY).context,
      ),
    ).rejects.toThrow(/cannot perform/);
  });

  it('lets only trusted proxy keys assert the acting user', async () => {
    const proxied = ctx('POST', WRITE_KEY, 'Analyst@Example.com');
    await setup().canActivate(proxied.context);
    expect(proxied.request.principal).toMatchObject({
      name: 'writer',
      actor: 'analyst@example.com',
    });

    const spoofed = ctx('GET', READ_KEY, 'boss@example.com');
    await setup().canActivate(spoofed.context);
    expect(spoofed.request.principal?.actor).toBe('reader'); // header ignored for untrusted keys

    await expect(
      setup().canActivate(ctx('POST', WRITE_KEY, 'bad header\n').context),
    ).rejects.toThrow(/x-acting-user/);
  });

  it('hashes keys with SHA-256 hex', () => {
    expect(hashApiKey('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});

describe('ApiKeyGuard — threat-feed user tokens', () => {
  const identities = (scope: 'read' | 'write' | 'admin' = 'write') => ({
    enabled: true,
    resolve: vi.fn(async () => ({
      userId: 'u1',
      email: 'ana@example.com',
      roleKey: 'analyst',
      scope,
    })),
  });

  it('authenticates a Bearer token as the user; x-acting-user is ignored', async () => {
    const id = identities();
    const { context, request } = ctx(
      'POST',
      undefined,
      'boss@example.com',
      'tok',
    );
    await expect(setup({}, id).canActivate(context)).resolves.toBe(true);
    expect(id.resolve).toHaveBeenCalledWith('tok');
    expect(request.principal).toEqual({
      name: 'user:ana@example.com',
      kind: 'user',
      scope: 'write',
      actor: 'ana@example.com',
    });
  });

  it("enforces the role's scope", async () => {
    await expect(
      setup({}, identities('read')).canActivate(
        ctx('POST', undefined, undefined, 'tok').context,
      ),
    ).rejects.toThrow(/role \("analyst"\) cannot perform/);
    await expect(
      setup({}, identities('read')).canActivate(
        ctx('GET', undefined, undefined, 'tok').context,
      ),
    ).resolves.toBe(true);
  });

  it('prefers the API key when both are present, and refuses Bearer when not enabled', async () => {
    const id = identities();
    await setup({}, id).canActivate(
      ctx('GET', READ_KEY, undefined, 'tok').context,
    );
    expect(id.resolve).not.toHaveBeenCalled();
    await expect(
      setup({}, { enabled: false }).canActivate(
        ctx('GET', undefined, undefined, 'tok').context,
      ),
    ).rejects.toThrow('Missing API key');
  });
});

describe('verifyHs256', () => {
  it('accepts a valid token and returns its claims', () => {
    expect(verifyHs256(jwt({ sub: 'u1', exp: exp() }), SECRET)).toMatchObject({
      sub: 'u1',
    });
  });

  it.each([
    [
      'wrong secret',
      () =>
        jwt({ sub: 'u1', exp: exp() }, 'HS256', 'another-secret-0123456789'),
    ],
    ['alg none', () => jwt({ sub: 'u1', exp: exp() }, 'none')],
    [
      'expired',
      () => jwt({ sub: 'u1', exp: Math.floor(Date.now() / 1000) - 120 }),
    ],
    ['no expiry', () => jwt({ sub: 'u1' })],
    ['no subject', () => jwt({ exp: exp() })],
    [
      'not yet valid',
      () =>
        jwt({
          sub: 'u1',
          exp: exp(),
          nbf: Math.floor(Date.now() / 1000) + 600,
        }),
    ],
    ['malformed', () => 'a.b'],
    ['garbage', () => 'x.y.z'],
  ])('rejects %s', (_label, make) => {
    expect(() => verifyHs256(make(), SECRET)).toThrow();
  });
});

describe('role → scope mapping', () => {
  it('maps threat-feed permissions like the manage-feed gateway does', () => {
    expect(scopeFor([{ key: '*', method: '*', path: '*' }])).toBe('admin');
    expect(
      scopeFor([
        { key: 'write', method: 'POST', path: '/feeds' },
        { key: 'read', method: 'GET', path: '*' },
      ]),
    ).toBe('write');
    expect(scopeFor([{ key: 'read', method: 'GET', path: '*' }])).toBe('read');
    expect(
      scopeFor([{ key: 'read', method: 'GET', path: '/sources' }]),
    ).toBeNull();
    expect(
      can(
        [{ key: 'write', method: 'PATCH', path: '/feeds/*' }],
        'PATCH',
        '/feeds/1',
      ),
    ).toBe(true);
  });
});

describe('UserIdentityService', () => {
  function svc(me: unknown, status = 200, secret: string | undefined = SECRET) {
    const store = new Map<string, string>();
    const redis = {
      get: vi.fn(async (k: string) => store.get(k) ?? null),
      set: vi.fn(async (k: string, v: string) => (store.set(k, v), 'OK')),
    };
    const config = {
      get: (k: string) =>
        k === 'auth'
          ? { jwtSecret: secret, identityCacheMs: 60_000 }
          : { url: 'http://tf/api/v1', timeoutMs: 1_000 },
    };
    const fetchMock = vi.fn(
      async () =>
        ({ status, ok: status < 400, json: async () => me }) as Response,
    );
    vi.stubGlobal('fetch', fetchMock);
    return {
      s: new UserIdentityService(config as never, redis as never),
      fetchMock,
      redis,
    };
  }
  afterEach(() => vi.unstubAllGlobals());

  const me = {
    id: 'u1',
    email: 'Ana@Example.com',
    role: { key: 'analyst' },
    permissions: [{ key: 'write', method: 'POST', path: '/feeds' }],
  };

  it('verifies locally, asks threat-feed once, then serves from cache', async () => {
    const { s, fetchMock } = svc(me);
    const token = jwt({ sub: 'u1', exp: exp() });
    expect(await s.resolve(token)).toEqual({
      userId: 'u1',
      email: 'ana@example.com',
      roleKey: 'analyst',
      scope: 'write',
    });
    await s.resolve(token);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]).toEqual([
      'http://tf/api/v1/auth/me',
      expect.objectContaining({
        headers: expect.objectContaining({ authorization: `Bearer ${token}` }),
      }),
    ]);
  });

  it('rejects bad tokens without calling threat-feed; maps threat-feed answers', async () => {
    const bad = svc(me);
    await expect(
      bad.s.resolve(
        jwt({ sub: 'u1', exp: exp() }, 'HS256', 'forged-secret-0123456789'),
      ),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(bad.fetchMock).not.toHaveBeenCalled();

    await expect(
      svc(me, 401).s.resolve(jwt({ sub: 'u1', exp: exp() })),
    ).rejects.toThrow('Session is no longer valid');
    await expect(
      svc(me, 503).s.resolve(jwt({ sub: 'u1', exp: exp() })),
    ).rejects.toThrow('Identity provider unavailable');
    await expect(
      svc({ ...me, permissions: [] }).s.resolve(jwt({ sub: 'u1', exp: exp() })),
    ).rejects.toBeInstanceOf(ForbiddenException);
    await expect(svc(me, 200, '').s.resolve('x')).rejects.toThrow(
      /AUTH_JWT_SECRET/,
    );
  });
});
