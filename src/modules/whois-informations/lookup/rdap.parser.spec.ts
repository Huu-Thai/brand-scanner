import { parseRdap, type RdapDomain } from './rdap.parser.js';

/** Trimmed real-world shape (Verisign registry + registrar entity, RFC 9083). */
const fixture: RdapDomain = {
  objectClassName: 'domain',
  ldhName: 'APYPAL.COM',
  status: ['client transfer prohibited'],
  port43: 'whois.verisign-grs.com',
  events: [
    { eventAction: 'registration', eventDate: '2001-05-04T17:39:28Z' },
    { eventAction: 'expiration', eventDate: '2027-05-04T17:39:28Z' },
    { eventAction: 'last changed', eventDate: '2026-04-30T09:12:00Z' },
  ],
  secureDNS: { delegationSigned: false },
  nameservers: [
    { ldhName: 'NS1.PARKING.EXAMPLE' },
    { ldhName: 'ns1.parking.example' },
    { ldhName: 'NS2.PARKING.EXAMPLE' },
  ],
  entities: [
    {
      roles: ['registrar'],
      vcardArray: [
        'vcard',
        [
          ['version', {}, 'text', '4.0'],
          ['fn', {}, 'text', 'GoDaddy.com, LLC'],
        ],
      ],
      entities: [
        {
          roles: ['abuse'],
          vcardArray: [
            'vcard',
            [
              ['fn', {}, 'text', ''],
              ['email', {}, 'text', 'Abuse@GoDaddy.com'],
            ],
          ],
        },
      ],
    },
    {
      roles: ['registrant'],
      vcardArray: [
        'vcard',
        [
          ['org', {}, 'text', 'Domains By Proxy, LLC'],
          ['adr', {}, 'text', ['', '', '', 'Tempe', 'AZ', '85281', 'US']],
        ],
      ],
    },
  ],
};

describe('parseRdap', () => {
  it('maps registrar, registrant, abuse contact, dates, nameservers and DNSSEC', () => {
    expect(parseRdap(fixture)).toEqual({
      registrar: 'GoDaddy.com, LLC',
      registrantOrg: 'Domains By Proxy, LLC',
      registrantCountry: 'US',
      abuseEmail: 'abuse@godaddy.com',
      emails: ['abuse@godaddy.com'],
      nameServers: ['ns1.parking.example', 'ns2.parking.example'],
      statuses: ['client transfer prohibited'],
      dnssec: 'unsigned',
      whoisServer: 'whois.verisign-grs.com',
      createdDate: new Date('2001-05-04T17:39:28Z'),
      updatedDate: new Date('2026-04-30T09:12:00Z'),
      expiresDate: new Date('2027-05-04T17:39:28Z'),
    });
  });

  it('tolerates a minimal object', () => {
    expect(parseRdap({ ldhName: 'x.com' })).toMatchObject({
      emails: [],
      nameServers: [],
      statuses: [],
      dnssec: undefined,
    });
  });
});
