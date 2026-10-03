import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../config/configuration.js';
import {
  jwtExpiry,
  ThreatFeedClient,
  ThreatFeedError,
} from './threat-feed.client.js';

const jwt = (exp: number) =>
  `h.${Buffer.from(JSON.stringify({ sub: 'u', exp })).toString('base64url')}.s`;

function json(status: number, body: unknown) {
  return { status, ok: status < 400, json: async () => body } as Response;
}

function setup(extra: Record<string, unknown> = {}) {
  const config = {
    get: () => ({
      ...extra,
      enabled: true,
      sourceName: 'Fuzzer Scanner',
      url: 'http://tf/api/v1',
      email: 'svc@x',
      password: 'pw',
      timeoutMs: 1000,
    }),
  } as unknown as ConfigService<AppConfig, true>;
  const fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
  return { client: new ThreatFeedClient(config), fetchMock };
}

const token = jwt(Math.floor(Date.now() / 1000) + 900);
const feeds = (values: string[]) => ({
  data: values.map((value) => ({ value, type: 'DOMAIN', severity: 'high' })),
});

describe('ThreatFeedClient', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('signs in once, reuses the token, and matches the indicator exactly (case-insensitive)', async () => {
    const { client, fetchMock } = setup();
    fetchMock.mockImplementation(async (url: string) =>
      url.endsWith('/auth/login')
        ? json(200, { accessToken: token })
        : json(200, feeds(['xapypal.com', 'APYPAL.com'])),
    );
    expect(
      (await client.findActiveIndicator('DOMAIN', 'apypal.com'))?.value,
    ).toBe('APYPAL.com');
    expect(await client.findActiveIndicator('DOMAIN', 'other.com')).toBeNull();
    const logins = fetchMock.mock.calls.filter(([u]) =>
      String(u).endsWith('/auth/login'),
    );
    expect(logins).toHaveLength(1);
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toContain('/feeds?type=DOMAIN&search=apypal.com&isActive=true');
    expect(init.headers.authorization).toBe(`Bearer ${token}`);
  });

  it('shares one login between concurrent callers', async () => {
    const { client, fetchMock } = setup();
    fetchMock.mockImplementation(async (url: string) =>
      url.endsWith('/auth/login')
        ? json(200, { accessToken: token })
        : json(200, feeds([])),
    );
    await Promise.all(
      [1, 2, 3].map(() => client.findActiveIndicator('IPV4', '1.2.3.4')),
    );
    expect(
      fetchMock.mock.calls.filter(([u]) => String(u).endsWith('/auth/login')),
    ).toHaveLength(1);
  });

  it('re-authenticates once on 401, then gives up with a typed error', async () => {
    const { client, fetchMock } = setup();
    let feedCalls = 0;
    fetchMock.mockImplementation(async (url: string) => {
      if (url.endsWith('/auth/login')) return json(200, { accessToken: token });
      return ++feedCalls === 1 ? json(401, {}) : json(200, feeds(['a.com']));
    });
    expect(await client.findActiveIndicator('DOMAIN', 'a.com')).not.toBeNull();
    expect(
      fetchMock.mock.calls.filter(([u]) => String(u).endsWith('/auth/login')),
    ).toHaveLength(2);

    fetchMock.mockImplementation(async (url: string) =>
      url.endsWith('/auth/login')
        ? json(200, { accessToken: token })
        : json(503, {}),
    );
    await expect(
      client.findActiveIndicator('DOMAIN', 'a.com'),
    ).rejects.toBeInstanceOf(ThreatFeedError);
  });

  it('surfaces login failures', async () => {
    const { client, fetchMock } = setup();
    fetchMock.mockResolvedValue(json(401, {}));
    await expect(client.findActiveIndicator('DOMAIN', 'a.com')).rejects.toThrow(
      /login failed: HTTP 401/,
    );
  });

  it('creates and updates indicators with JSON bodies', async () => {
    const { client, fetchMock } = setup();
    fetchMock.mockImplementation(async (url: string) =>
      url.endsWith('/auth/login')
        ? json(200, { accessToken: token })
        : json(200, { id: 'f1' }),
    );
    await client.createIndicator({
      value: 'a.com',
      type: 'DOMAIN',
      sourceId: 's',
    });
    await client.updateIndicator('f1', { isActive: false });
    const [, create] = fetchMock.mock.calls[1];
    expect(create).toMatchObject({
      method: 'POST',
      body: JSON.stringify({ value: 'a.com', type: 'DOMAIN', sourceId: 's' }),
    });
    expect(create.headers['content-type']).toBe('application/json');
    const [url, update] = fetchMock.mock.calls[2];
    expect(url).toBe('http://tf/api/v1/feeds/f1');
    expect(update).toMatchObject({
      method: 'PATCH',
      body: '{"isActive":false}',
    });
  });

  it('resolves the publishing source by name, creating it once when missing', async () => {
    const { client, fetchMock } = setup();
    fetchMock.mockImplementation(async (url: string, init: RequestInit) => {
      if (url.endsWith('/auth/login')) return json(200, { accessToken: token });
      return init.method === 'POST'
        ? json(201, { id: 'new-src' })
        : json(200, [{ id: 'x', name: 'Other' }]);
    });
    expect(await client.sourceId()).toBe('new-src');
    expect(await client.sourceId()).toBe('new-src');
    expect(
      fetchMock.mock.calls.filter(([u]) => String(u).endsWith('/sources')),
    ).toHaveLength(2); // GET + POST, then cached
  });

  it('uses a configured source id without any lookup', async () => {
    const { client, fetchMock } = setup({ sourceId: 'cfg-src' });
    expect(await client.sourceId()).toBe('cfg-src');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('explains 403s as missing service-account permissions', async () => {
    const { client, fetchMock } = setup();
    fetchMock.mockImplementation(async (url: string) =>
      url.endsWith('/auth/login')
        ? json(200, { accessToken: token })
        : json(403, {}),
    );
    await expect(
      client.createIndicator({ value: 'a.com', type: 'DOMAIN', sourceId: 's' }),
    ).rejects.toMatchObject({
      status: 403,
      message: expect.stringMatching(
        /POST \/feeds → HTTP 403: .*lacks this permission/,
      ),
    });
  });

  it('reads the JWT expiry, defaulting when unreadable', () => {
    expect(jwtExpiry(jwt(2_000_000_000))).toBe(2_000_000_000_000);
    expect(jwtExpiry('garbage')).toBeGreaterThan(Date.now());
  });
});
