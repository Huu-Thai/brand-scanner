import type { RdapClient } from './rdap.client.js';
import type { Whois43Client } from './whois43.client.js';
import {
  WhoisLookupService,
  WhoisUnavailableError,
} from './whois-lookup.service.js';

function setup(rdap: unknown, whois43: unknown) {
  const r = { lookup: vi.fn(async () => rdap) } as unknown as RdapClient;
  const w = { lookup: vi.fn(async () => whois43) } as unknown as Whois43Client;
  return { service: new WhoisLookupService(r, w), r, w };
}

const record = {
  registrar: 'GoDaddy',
  emails: [],
  nameServers: ['ns1.x'],
  statuses: [],
  createdDate: new Date('2020-01-01'),
};

describe('WhoisLookupService', () => {
  it('uses RDAP for the registrable domain when available', async () => {
    const { service, r, w } = setup(
      { kind: 'found', record, raw: '{"x":1}' },
      null,
    );
    const result = await service.lookup('login.apypal.com');
    expect(r.lookup).toHaveBeenCalledWith('apypal.com');
    expect(w.lookup).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      source: 'RDAP',
      queriedDomain: 'apypal.com',
      parseSucceeded: true,
    });
  });

  it('falls back to port-43 WHOIS and parses the text', async () => {
    const text =
      'Registrar: NameCheap\nCreation Date: 2021-03-04\nName Server: NS1.X.COM\nabuse@namecheap.com\n';
    const { service } = setup(
      { kind: 'unsupported' },
      { kind: 'found', text, server: 'whois.x' },
    );
    const result = await service.lookup('x.co');
    expect(result).toMatchObject({
      source: 'WHOIS',
      parseSucceeded: true,
      record: {
        registrar: 'NameCheap',
        abuseEmail: 'abuse@namecheap.com',
        nameServers: ['ns1.x.com'],
      },
    });
    expect(result.record.createdDate?.toISOString()).toBe(
      '2021-03-04T00:00:00.000Z',
    );
  });

  it('records a definitive RDAP 404 when port 43 cannot answer', async () => {
    const { service } = setup(
      { kind: 'not_found' },
      { kind: 'error', message: 'no server' },
    );
    expect(await service.lookup('x.com')).toMatchObject({
      source: 'RDAP',
      parseSucceeded: false,
      rawText: 'RDAP: 404 Not Found',
    });
  });

  it('throws a retryable error when nothing could answer', async () => {
    const { service } = setup(
      { kind: 'error', message: 'RDAP 503' },
      { kind: 'rate_limited', server: 'whois.x' },
    );
    await expect(service.lookup('x.com')).rejects.toThrow(
      WhoisUnavailableError,
    );
    await expect(service.lookup('x.com')).rejects.toThrow(
      /RDAP 503; WHOIS whois.x rate-limited/,
    );
  });
});
