import { InvalidDomainError, normalizeDomain } from './domain.js';

describe('normalizeDomain', () => {
  it('lower-cases, strips the trailing dot and keeps subdomains', () => {
    expect(normalizeDomain(' Login.PayPal.com. ')).toEqual({
      ascii: 'login.paypal.com',
      unicode: 'login.paypal.com',
      registrable: 'paypal.com',
    });
  });

  it('converts IDN to punycode and back', () => {
    expect(normalizeDomain('münchen.info')).toMatchObject({
      ascii: 'xn--mnchen-3ya.info',
      unicode: 'münchen.info',
    });
  });

  it('understands multi-label public suffixes', () => {
    expect(normalizeDomain('example.co.uk').registrable).toBe('example.co.uk');
  });

  it.each([
    ['https://example.com', /bare hostname/],
    ['example.com/login', /bare hostname/],
    ['example.com:443', /bare hostname/],
    ['user@example.com', /bare hostname/],
    ['192.168.0.1', /IP addresses/],
    ['co.uk', /no registrable domain/],
    ['localhost', /no registrable domain/],
    ['-bad-.com', /not a valid domain/],
    ['', /bare hostname/],
  ])('rejects %s', (input, message) => {
    expect(() => normalizeDomain(input)).toThrow(InvalidDomainError);
    expect(() => normalizeDomain(input)).toThrow(message);
  });
});
