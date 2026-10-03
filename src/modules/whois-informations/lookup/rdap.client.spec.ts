import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../../config/configuration.js';
import { RdapClient } from './rdap.client.js';

const bootstrap = {
  services: [
    [
      ['com', 'net'],
      ['http://rdap.example/', 'https://rdap.verisign.example/com/v1/'],
    ],
  ],
};
const res = (status: number, body: unknown) =>
  ({
    status,
    ok: status < 400,
    json: async () => body,
    text: async () => JSON.stringify(body),
  }) as Response;

function setup(
  domainStatus: number | Error,
  body: unknown = { ldhName: 'X.COM', events: [] },
) {
  const config = {
    get: () => ({
      whoisTimeoutMs: 1000,
      rdapBootstrapUrl: 'https://data.iana.org/rdap/dns.json',
    }),
  } as unknown as ConfigService<AppConfig, true>;
  const fetchMock = vi.fn(async (url: string) => {
    if (url.includes('data.iana.org')) return res(200, bootstrap);
    if (domainStatus instanceof Error) throw domainStatus;
    return res(domainStatus, body);
  });
  vi.stubGlobal('fetch', fetchMock);
  return { client: new RdapClient(config), fetchMock };
}

describe('RdapClient', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('prefers the https service from the bootstrap and parses the domain', async () => {
    const { client, fetchMock } = setup(200);
    expect(await client.lookup('x.com')).toMatchObject({
      kind: 'found',
      record: { emails: [] },
    });
    expect(fetchMock.mock.calls[1][0]).toBe(
      'https://rdap.verisign.example/com/v1/domain/x.com',
    );
  });

  it('caches the bootstrap between lookups', async () => {
    const { client, fetchMock } = setup(200);
    await client.lookup('a.com');
    await client.lookup('b.net');
    expect(
      fetchMock.mock.calls.filter(([u]) => String(u).includes('iana')).length,
    ).toBe(1);
  });

  it('maps 404, other HTTP errors, network errors and unsupported TLDs', async () => {
    expect(await setup(404).client.lookup('x.com')).toEqual({
      kind: 'not_found',
    });
    expect(await setup(503).client.lookup('x.com')).toMatchObject({
      kind: 'error',
      message: expect.stringContaining('503'),
    });
    expect(
      await setup(new Error('ECONNRESET')).client.lookup('x.com'),
    ).toMatchObject({ kind: 'error' });
    expect(await setup(200).client.lookup('x.zz')).toEqual({
      kind: 'unsupported',
    });
  });

  it('reports an unavailable bootstrap as an error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => res(500, {})),
    );
    const config = {
      get: () => ({
        whoisTimeoutMs: 1000,
        rdapBootstrapUrl: 'https://data.iana.org/rdap/dns.json',
      }),
    } as unknown as ConfigService<AppConfig, true>;
    expect(await new RdapClient(config).lookup('x.com')).toMatchObject({
      kind: 'error',
      message: /bootstrap/,
    });
  });
});
