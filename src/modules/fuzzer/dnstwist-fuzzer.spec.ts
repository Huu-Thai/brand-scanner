import { DnstwistFuzzer, parseDomain } from './dnstwist-fuzzer.js';

// Technique-level behaviour, ported from Reporting's dnstwist-fuzzer.util.spec.ts.
const f = new DnstwistFuzzer('google.com');

describe('parseDomain', () => {
  it('uses the Public Suffix List for multi-label TLDs', () => {
    expect(parseDomain('robi.com.bd')).toEqual({
      subdomain: '',
      domain: 'robi',
      tld: 'com.bd',
    });
    expect(parseDomain('Login.Example.co.uk.')).toEqual({
      subdomain: 'login',
      domain: 'example',
      tld: 'co.uk',
    });
  });

  it('falls back to label splitting for unknown suffixes', () => {
    expect(parseDomain('localhost')).toEqual({
      subdomain: '',
      domain: 'localhost',
      tld: '',
    });
  });
});

describe('DnstwistFuzzer techniques', () => {
  it('omission removes each character once', () => {
    expect(f.omission()).toHaveLength('google'.length);
    expect(f.omission()[0]).toBe('oogle');
  });

  it('transposition swaps adjacent characters', () => {
    expect(f.transposition()).toHaveLength('google'.length - 1);
    expect(f.transposition()[0]).toBe('ogogle');
  });

  it('repetition doubles one character', () => {
    f.repetition().forEach((d) => expect(d).toHaveLength('google'.length + 1));
  });

  it('hyphenation inserts hyphens', () => {
    expect(f.hyphenation()).toHaveLength('google'.length);
    f.hyphenation().forEach((d) => expect(d).toContain('-'));
  });

  it('addition appends and prepends characters', () => {
    expect(f.addition().length).toBeGreaterThan(0);
    f.addition().forEach((d) =>
      expect(d.length).toBeGreaterThan('google'.length),
    );
  });

  it('bitsquatting, homoglyph and vowel swap produce variants', () => {
    expect(f.bitsquatting().length).toBeGreaterThan(0);
    expect(f.homoglyph().length).toBeGreaterThan(0);
    f.vowelSwap().forEach((d) => expect(d).toHaveLength('google'.length));
  });

  it('cyrillic only substitutes when every character has a Cyrillic twin', () => {
    expect(new DnstwistFuzzer('aceo.com').cyrillic()).toEqual(['асео']);
    expect(new DnstwistFuzzer('zzz.com').cyrillic()).toEqual([]);
  });
});

describe('DnstwistFuzzer.generate', () => {
  const perms = f.generate();

  it('starts with the *original baseline', () => {
    expect(perms[0]).toEqual({ fuzzer: '*original', domain: 'google.com' });
  });

  it('deduplicates by domain', () => {
    expect(new Set(perms.map((p) => p.domain)).size).toBe(perms.length);
  });

  it('emits ASCII (punycode) domains only', () => {
    perms.forEach((p) => expect(p.domain).toMatch(/^[a-z0-9.-]+$/));
    expect(perms.some((p) => p.domain.startsWith('xn--'))).toBe(true);
  });

  it('keeps compound TLDs intact for core techniques', () => {
    const uk = new DnstwistFuzzer('example.co.uk').generate();
    uk.filter((p) =>
      ['omission', 'transposition', 'replacement'].includes(p.fuzzer),
    ).forEach((p) => expect(p.domain.endsWith('.co.uk')).toBe(true));
  });
});
