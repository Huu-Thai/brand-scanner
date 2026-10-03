// Ported from Reporting tests/unit/modules/wsd-scanner-worker/whois-parser.util.spec.ts —
// the parser is a verbatim port, so it is held to the same registry fixtures.
import { parseWhoisDate, parseWhois } from './whois-parser.js';

// ─── parseWhoisDate ────────────────────────────────────────────────────────────

describe('parseWhoisDate', () => {
  it('returns undefined for empty string', () => {
    expect(parseWhoisDate('')).toBeUndefined();
    expect(parseWhoisDate('   ')).toBeUndefined();
  });

  it('parses ISO 8601 with offset', () => {
    const d = parseWhoisDate('2024-03-15T10:30:00Z');
    expect(d).toBeInstanceOf(Date);
    expect(d!.getUTCFullYear()).toBe(2024);
    expect(d!.getUTCMonth()).toBe(2); // March = 2
    expect(d!.getUTCDate()).toBe(15);
  });

  it('parses ISO 8601 with timezone offset', () => {
    const d = parseWhoisDate('2024-01-10T00:00:00+05:30');
    expect(d).toBeInstanceOf(Date);
    expect(d!.getUTCFullYear()).toBe(2024);
  });

  it('parses compact YYYYMMDD', () => {
    const d = parseWhoisDate('20250105');
    expect(d).toBeInstanceOf(Date);
    expect(d!.getUTCFullYear()).toBe(2025);
    expect(d!.getUTCMonth()).toBe(0); // Jan
    expect(d!.getUTCDate()).toBe(5);
  });

  it('parses dotted YYYY.MM.DD', () => {
    const d = parseWhoisDate('2025.01.05');
    expect(d).toBeInstanceOf(Date);
    expect(d!.getUTCFullYear()).toBe(2025);
    expect(d!.getUTCMonth()).toBe(0);
    expect(d!.getUTCDate()).toBe(5);
  });

  it('parses DD.MM.YYYY (European format)', () => {
    const d = parseWhoisDate('15.03.2024');
    expect(d).toBeInstanceOf(Date);
    expect(d!.getUTCFullYear()).toBe(2024);
    expect(d!.getUTCMonth()).toBe(2); // March
    expect(d!.getUTCDate()).toBe(15);
  });

  it('parses DD/MM/YYYY (day > 12 forces the regex path)', () => {
    // '05/01/2025' is ambiguous — native Date parses it as MM/DD (May 1).
    // Use day=15 which native MM/DD would treat as month 15 (invalid) → falls through to regex.
    const d = parseWhoisDate('15/03/2024');
    expect(d).toBeInstanceOf(Date);
    expect(d!.getUTCFullYear()).toBe(2024);
    expect(d!.getUTCMonth()).toBe(2); // March
    expect(d!.getUTCDate()).toBe(15);
  });

  it('parses YYYY.MM.DD HH:MM:SS', () => {
    const d = parseWhoisDate('2025.01.05 12:30:00');
    expect(d).toBeInstanceOf(Date);
    expect(d!.getUTCFullYear()).toBe(2025);
    expect(d!.getUTCHours()).toBe(12);
    expect(d!.getUTCMinutes()).toBe(30);
  });

  it('parses DD-Mon-YYYY (e.g. 05-Jan-2025)', () => {
    const d = parseWhoisDate('05-Jan-2025');
    expect(d).toBeInstanceOf(Date);
    expect(d!.getUTCFullYear()).toBe(2025);
    expect(d!.getUTCMonth()).toBe(0);
    expect(d!.getUTCDate()).toBe(5);
  });

  it('parses DD Mon YYYY with full month name', () => {
    const d = parseWhoisDate('5 January 2025');
    expect(d).toBeInstanceOf(Date);
    expect(d!.getUTCMonth()).toBe(0);
  });

  it('parses YYYY-Mon-DD (e.g. 2025-Jan-05)', () => {
    const d = parseWhoisDate('2025-Jan-05');
    expect(d).toBeInstanceOf(Date);
    expect(d!.getUTCFullYear()).toBe(2025);
    expect(d!.getUTCMonth()).toBe(0);
    expect(d!.getUTCDate()).toBe(5);
  });

  it('parses Mon DD YYYY (e.g. Jan 05 2025)', () => {
    const d = parseWhoisDate('Jan 05 2025');
    expect(d).toBeInstanceOf(Date);
    expect(d!.getUTCFullYear()).toBe(2025);
  });

  it('replaces JST timezone abbreviation', () => {
    const d = parseWhoisDate('2024-06-15T10:00:00 JST');
    expect(d).toBeInstanceOf(Date);
    expect(d!.getUTCHours()).toBe(1); // 10:00 JST = 01:00 UTC
  });

  it('strips ordinal suffixes (1st, 2nd, 3rd, 4th)', () => {
    const d = parseWhoisDate('5th January 2025');
    expect(d).toBeInstanceOf(Date);
    expect(d!.getUTCMonth()).toBe(0);
  });

  it('strips parenthetical timezone (JST)', () => {
    const d = parseWhoisDate('2025-01-05T00:00:00(JST)');
    expect(d).toBeInstanceOf(Date);
    expect(d!.getUTCFullYear()).toBe(2025);
  });

  it('returns undefined for garbage input', () => {
    expect(parseWhoisDate('not a date')).toBeUndefined();
    // 'abc xyz 999' — V8 can parse '999' as year 999; use fully unparseable input instead
    expect(parseWhoisDate('completely invalid string here')).toBeUndefined();
  });
});

// ─── parseWhois ───────────────────────────────────────────────────────────────

const SAMPLE_RDAP = `
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: http://www.markmonitor.com
Updated Date: 2024-08-14T07:01:38Z
Creation Date: 2000-01-14T00:00:00Z
Registry Expiry Date: 2026-01-13T00:00:00Z
Registrar: MarkMonitor Inc.
Domain Status: clientDeleteProhibited
Domain Status: clientTransferProhibited
Registrant Name: Domain Administrator
Registrant Organization: Example, Inc.
Registrant Street: 1 Hacker Way
Registrant City: Menlo Park
Registrant State/Province: CA
Registrant Postal Code: 94025
Registrant Country: US
Registrant Phone: +1.6505434800
Admin Name: Domain Administrator
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
DNSSEC: unsigned
`;

describe('parseWhois — RDAP-style', () => {
  const result = parseWhois(SAMPLE_RDAP);

  it('extracts registrar', () => {
    expect(result.registrar).toBe('MarkMonitor Inc.');
  });

  it('extracts whoisServer', () => {
    expect(result.whoisServer).toBe('whois.markmonitor.com');
  });

  it('extracts creationDate', () => {
    expect(result.creationDate).toBeInstanceOf(Date);
    expect(result.creationDate!.getUTCFullYear()).toBe(2000);
  });

  it('extracts updatedDate', () => {
    expect(result.updatedDate).toBeInstanceOf(Date);
    expect(result.updatedDate!.getUTCFullYear()).toBe(2024);
  });

  it('extracts expirationDate', () => {
    expect(result.expirationDate).toBeInstanceOf(Date);
    expect(result.expirationDate!.getUTCFullYear()).toBe(2026);
  });

  it('extracts org', () => {
    expect(result.org).toBe('Example, Inc.');
  });

  it('extracts city', () => {
    expect(result.city).toBe('Menlo Park');
  });

  it('extracts state', () => {
    expect(result.state).toBe('CA');
  });

  it('extracts zipcode', () => {
    expect(result.zipcode).toBe('94025');
  });

  it('extracts country', () => {
    expect(result.country).toBe('US');
  });

  it('extracts phone', () => {
    expect(result.phone).toBe('+1.6505434800');
  });

  it('extracts adminName', () => {
    expect(result.adminName).toBe('Domain Administrator');
  });

  it('extracts nameServers (lowercased)', () => {
    expect(result.nameServers).toContain('a.iana-servers.net');
    expect(result.nameServers).toContain('b.iana-servers.net');
    expect(result.nameServers).toHaveLength(2);
  });

  it('extracts status (deduped)', () => {
    expect(result.status).toContain('clientDeleteProhibited');
    expect(result.status).toContain('clientTransferProhibited');
  });

  it('extracts dnssec', () => {
    expect(result.dnssec).toBe('unsigned');
  });
});

describe('parseWhois — ccTLD and legacy formats', () => {
  it('extracts "last-changed" as updatedDate', () => {
    const r = parseWhois('last-changed: 2024-05-01T00:00:00Z\n');
    expect(r.updatedDate).toBeInstanceOf(Date);
    expect(r.updatedDate!.getUTCFullYear()).toBe(2024);
  });

  it('extracts "paid-till" as expirationDate', () => {
    const r = parseWhois('paid-till: 2026.12.31\n');
    expect(r.expirationDate).toBeInstanceOf(Date);
    expect(r.expirationDate!.getUTCFullYear()).toBe(2026);
  });

  it('extracts "nserver" as nameServers', () => {
    const r = parseWhois(
      'nserver: ns1.example.com\nnserver: ns2.example.com\n',
    );
    expect(r.nameServers).toContain('ns1.example.com');
    expect(r.nameServers).toHaveLength(2);
  });

  it('extracts "organisation" as org (UK WHOIS)', () => {
    const r = parseWhois('organisation: Acme Ltd.\n');
    expect(r.org).toBe('Acme Ltd.');
  });

  it('extracts "[Created on]" (JPRS format)', () => {
    const r = parseWhois('[Created on]              2018-01-10\n');
    expect(r.creationDate).toBeInstanceOf(Date);
    expect(r.creationDate!.getUTCFullYear()).toBe(2018);
  });

  it('extracts "[Expires on]" (JPRS format)', () => {
    const r = parseWhois('[Expires on]              2027-01-10\n');
    expect(r.expirationDate).toBeInstanceOf(Date);
    expect(r.expirationDate!.getUTCFullYear()).toBe(2027);
  });
});

describe('parseWhois — .tr (TRABIS) format', () => {
  // Real-world sample from whois.trabis.gov.tr — the registrar's org name lives under a
  // "** Registrar:" section header (captured as `org`, since it's not on a "Registrar:" line
  // itself), and dates use a dot-leader separator style.
  const SAMPLE_TR = [
    '** Domain Name: test.info.tr',
    'Domain Status: Active',
    '',
    '** Registrar:',
    'NIC Handle\t\t: adh83',
    'Organization Name\t: ATAK DOMAIN BILGI TEKNOLOJILERI',
    'Address\t\t\t: Istasyon Mahallesi, Efe Sadik Caddesi,',
    '\t\t\t  No: 4, Kartepe 41000 Kocaeli Turkiye',
    'Phone\t\t\t: 90-262-3259222-',
    'Fax\t\t\t: 90-262-3249426-',
    '',
    '** Domain Servers:',
    'ns1.ankarahosting.web.tr',
    'ns2.ankarahosting.web.tr',
    '',
    '** Additional Info:',
    'Created on..............: 2017-Jun-01.',
    'Expires on..............: 2027-May-31.',
    '',
  ].join('\n');

  const result = parseWhois(SAMPLE_TR);

  it('extracts org from "Organization Name" under the Registrar section', () => {
    expect(result.org).toBe('ATAK DOMAIN BILGI TEKNOLOJILERI');
  });

  it('extracts address from a bare "Address:" line (no registrant/owner prefix)', () => {
    expect(result.address).toBe('Istasyon Mahallesi, Efe Sadik Caddesi,');
  });

  it('extracts phone from a bare "Phone:" line (no registrant/owner prefix)', () => {
    expect(result.phone).toBe('90-262-3259222-');
  });

  it('extracts creationDate from a dot-leader "Created on..............:" line', () => {
    expect(result.creationDate).toBeInstanceOf(Date);
    expect(result.creationDate!.getUTCFullYear()).toBe(2017);
    expect(result.creationDate!.getUTCMonth()).toBe(5); // Jun
    expect(result.creationDate!.getUTCDate()).toBe(1);
  });

  it('extracts expirationDate from a dot-leader "Expires on..............:" line', () => {
    expect(result.expirationDate).toBeInstanceOf(Date);
    expect(result.expirationDate!.getUTCFullYear()).toBe(2027);
    expect(result.expirationDate!.getUTCMonth()).toBe(4); // May
    expect(result.expirationDate!.getUTCDate()).toBe(31);
  });

  it('still extracts nameServers and status', () => {
    expect(result.nameServers).toContain('ns1.ankarahosting.web.tr');
    expect(result.status).toContain('Active');
  });
});

describe('parseWhois — emails', () => {
  it('extracts emails from body', () => {
    const r = parseWhois('abuse@example.com\ntech@registrar.net\n');
    expect(r.emails).toContain('abuse@example.com');
    expect(r.emails).toContain('tech@registrar.net');
  });

  it('deduplicates emails', () => {
    const r = parseWhois('abuse@example.com\nabuse@example.com\n');
    expect(r.emails).toHaveLength(1);
  });
});

describe('parseWhois — comment line skipping', () => {
  it('skips lines starting with %', () => {
    const r = parseWhois(
      '% This is a WHOIS comment\nRegistrar: Test Registrar\n',
    );
    expect(r.registrar).toBe('Test Registrar');
  });
});

describe('parseWhois — empty/garbage input', () => {
  it('returns empty object for empty string', () => {
    const r = parseWhois('');
    expect(r.registrar).toBeUndefined();
    expect(r.creationDate).toBeUndefined();
    expect(r.nameServers).toBeUndefined();
  });

  it('does not extract IP addresses as nameServers', () => {
    const r = parseWhois('Name Server: 8.8.8.8\n');
    expect(r.nameServers).toBeUndefined();
  });
});
