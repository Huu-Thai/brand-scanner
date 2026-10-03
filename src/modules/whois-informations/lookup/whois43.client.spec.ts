import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../../config/configuration.js';
import { Whois43Client } from './whois43.client.js';

const config = {
  get: () => ({ whoisTimeoutMs: 1000 }),
} as unknown as ConfigService<AppConfig, true>;
const thin =
  'Domain Name: EXAMPEL.COM\nRegistrar: NameCheap\nRegistrar WHOIS Server: whois.namecheap.com\nCreation Date: 2020-01-01T00:00:00Z\n';
const thick =
  'Domain name: exampel.com\nRegistrar: NameCheap, Inc.\nRegistrant Organization: Privacy service\nCreation Date: 2020-01-01T00:00:00Z\n';

describe('Whois43Client', () => {
  it('queries the mapped registry server, then follows the registrar referral for the thick record', async () => {
    const client = new Whois43Client(config);
    const raw = vi
      .spyOn(client, 'raw')
      .mockImplementation(async (_q, server) =>
        server === 'whois.namecheap.com' ? thick : thin,
      );
    expect(await client.lookup('exampel.com')).toEqual({
      kind: 'found',
      text: thick,
      server: 'whois.namecheap.com',
    });
    expect(raw.mock.calls.map(([, s]) => s)).toEqual([
      'whois.verisign-grs.com',
      'whois.namecheap.com',
    ]);
  });

  it('keeps the registry answer if the referral fails', async () => {
    const client = new Whois43Client(config);
    vi.spyOn(client, 'raw').mockImplementation(async (_q, server) => {
      if (server === 'whois.namecheap.com') throw new Error('timeout');
      return thin;
    });
    expect(await client.lookup('exampel.com')).toMatchObject({
      kind: 'found',
      server: 'whois.verisign-grs.com',
    });
  });

  it('treats "No match" as definitive', async () => {
    const client = new Whois43Client(config);
    vi.spyOn(client, 'raw').mockResolvedValue('No match for "NOPE.COM".');
    expect(await client.lookup('nope.com')).toMatchObject({
      kind: 'not_found',
    });
  });

  it('discovers unknown TLD servers via IANA and caches them', async () => {
    const client = new Whois43Client(config);
    const raw = vi
      .spyOn(client, 'raw')
      .mockImplementation(async (q, server) =>
        server === 'whois.iana.org'
          ? 'whois:        whois.nic.zzz\n'
          : `Domain: ${q}\nRegistrar: X\ncreated: 2020\n` + 'z'.repeat(40),
      );
    await client.lookup('a.zzz');
    await client.lookup('b.zzz');
    expect(
      raw.mock.calls.filter(([, s]) => s === 'whois.iana.org'),
    ).toHaveLength(1);
  });

  it('reports errors and unknown servers', async () => {
    const client = new Whois43Client(config);
    vi.spyOn(client, 'raw').mockRejectedValue(new Error('ECONNREFUSED'));
    expect(await client.lookup('x.com')).toMatchObject({
      kind: 'error',
      message: expect.stringContaining('ECONNREFUSED'),
    });
    expect(await client.lookup('x.zzz')).toMatchObject({
      kind: 'error',
      message: expect.stringContaining('No WHOIS server'),
    });
  });
});
