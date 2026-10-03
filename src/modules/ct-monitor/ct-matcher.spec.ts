import {
  brandTarget,
  editDistance,
  matchCertificate,
  skeleton,
  type BrandTarget,
} from './ct-matcher.js';

const opts = { minKeywordLength: 5, maxEditDistance: 2 };
const brands = [
  brandTarget('p', 'paypal.com'),
  brandTarget('n', 'northwindtraders.co.uk'),
  brandTarget('i', 'ing.com'),
].filter((b): b is BrandTarget => !!b);
const match = (...names: string[]) =>
  matchCertificate(names, brands, opts).map(
    (m) => `${m.brand}:${m.domain}:${m.kind}`,
  );

describe('CT matcher', () => {
  it('builds brand targets from registrable domains (multi-label suffixes too)', () => {
    expect(brandTarget('n', 'www.northwindtraders.co.uk')).toMatchObject({
      domain: 'northwindtraders.co.uk',
      label: 'northwindtraders',
    });
    expect(brandTarget('x', 'localhost')).toBeNull();
  });

  it('normalises homoglyphs and ASCII confusables', () => {
    expect(skeleton('paypa1')).toBe(skeleton('paypal'));
    expect(skeleton('pаypal')).toBe(skeleton('paypal')); // Cyrillic а
    expect(skeleton('xn--pypal-4ve')).toBe(skeleton('paypal')); // punycode of pаypal
    expect(skeleton('rnicrosoft')).toBe(skeleton('microsoft'));
    expect(skeleton('pay-pal')).toBe(skeleton('paypal'));
  });

  it('computes Damerau–Levenshtein with transpositions and an early exit', () => {
    expect(editDistance('paypal', 'paypal')).toBe(0);
    expect(editDistance('paypal', 'apypal')).toBe(1);
    expect(editDistance('paypal', 'paypall')).toBe(1);
    expect(editDistance('paypal', 'pyapl')).toBe(2);
    expect(editDistance('paypal', 'amazon', 2)).toBe(3);
  });

  it('flags typos, homoglyphs, TLD swaps, combos and brand-in-subdomain', () => {
    expect(match('paypa1.com')).toEqual(['paypal.com:paypa1.com:typo']);
    expect(match('xn--pypal-4ve.com')).toEqual([
      'paypal.com:xn--pypal-4ve.com:typo',
    ]);
    expect(match('*.paypal.net')).toEqual(['paypal.com:paypal.net:tld-swap']);
    expect(match('paypal-secure-login.com')).toEqual([
      'paypal.com:paypal-secure-login.com:combo',
    ]);
    expect(match('paypal.com.account-verify.xyz')).toEqual([
      'paypal.com:account-verify.xyz:subdomain',
    ]);
    expect(match('northwindtradres.co.uk')).toEqual([
      'northwindtraders.co.uk:northwindtradres.co.uk:typo',
    ]);
  });

  it('ignores the brand itself, unrelated names and short-keyword noise', () => {
    expect(match('www.paypal.com', 'paypal.com', 'api.paypal.com')).toEqual([]);
    expect(match('example.org', 'paycheck.com', 'google.com')).toEqual([]);
    // "ing" is too short for substring matches (booking.com, ingest.io, …) — only typos count.
    expect(match('booking.com', 'ingest.io', 'mailing.net')).toEqual([]);
    expect(match('ing.net')).toEqual(['ing.com:ing.net:tld-swap']);
  });

  it('reports one match per brand + domain, the strongest kind winning', () => {
    const m = matchCertificate(
      ['login.paypal.secure.xyz', 'paypal.xyz', 'www.paypal.xyz'],
      brands,
      opts,
    );
    expect(m).toHaveLength(2);
    expect(m.find((x) => x.domain === 'paypal.xyz')).toMatchObject({
      kind: 'tld-swap',
      certName: 'paypal.xyz',
    });
    expect(m.find((x) => x.domain === 'secure.xyz')).toMatchObject({
      kind: 'subdomain',
    });
  });
});
