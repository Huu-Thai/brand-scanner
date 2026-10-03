import {
  hasWhoisData,
  isDomainNotFound,
  isRateLimited,
  isValidDomainResponse,
  registrarReferral,
} from './whois-text.js';

describe('WHOIS text heuristics', () => {
  it('detects registry throttling', () => {
    expect(isRateLimited('Error 429')).toBe(true);
    expect(
      isRateLimited(
        'You have exceeded your access quota. Please try again later.',
      ),
    ).toBe(true);
    expect(isRateLimited('Registrar: Example')).toBe(false);
  });

  it('detects definitive not-found answers', () => {
    expect(isDomainNotFound('No match for "EXAMPEL.COM".')).toBe(true);
    expect(isDomainNotFound('%% NOT FOUND')).toBe(true);
    expect(isDomainNotFound('Domain Name: EXAMPEL.COM')).toBe(false);
  });

  it('recognises real registration data but not "available" answers or IANA stubs', () => {
    expect(
      hasWhoisData('Registrar: NameCheap\nCreation Date: 2020-01-01'),
    ).toBe(true);
    expect(hasWhoisData('Domain not found. Status: available')).toBe(false);
    expect(
      isValidDomainResponse(
        '% IANA WHOIS server\nsource:       IANA ' + 'x'.repeat(60),
      ),
    ).toBe(false);
    expect(isValidDomainResponse('Domain Name: X\n' + 'y'.repeat(60))).toBe(
      true,
    );
  });

  it('extracts the thick-registry referral', () => {
    expect(
      registrarReferral(
        'Domain Name: X\n   Registrar WHOIS Server: whois.namecheap.com\n',
      ),
    ).toBe('whois.namecheap.com');
    expect(registrarReferral('Registrar WHOIS Server: \n')).toBeUndefined();
  });
});
