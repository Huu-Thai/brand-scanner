import { domainToASCII, domainToUnicode } from 'node:url';
import { parse } from 'tldts';

export interface NormalizedDomain {
  /** ASCII / punycode form — what is stored and resolved. */
  ascii: string;
  /** Human-readable form (IDN decoded). */
  unicode: string;
  /** Registrable part, e.g. `example.co.uk`. */
  registrable: string;
}

export class InvalidDomainError extends Error {}

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/**
 * Normalises user input to a monitorable hostname: lower-cased, trailing dot removed,
 * IDN → punycode, must have a registrable domain under a known public suffix (PSL),
 * and must not be an IP address or a bare suffix.
 */
export function normalizeDomain(input: string): NormalizedDomain {
  const trimmed = input.trim().toLowerCase().replace(/\.$/, '');
  if (!trimmed || /[\s/:@?#]/.test(trimmed)) {
    throw new InvalidDomainError(
      'Enter a bare hostname such as "example.com" (no scheme, path or port)',
    );
  }
  const ascii = domainToASCII(trimmed);
  if (
    !ascii ||
    ascii.length > 253 ||
    !ascii.split('.').every((l) => LABEL.test(l))
  ) {
    throw new InvalidDomainError(`"${input}" is not a valid domain name`);
  }
  const parsed = parse(ascii);
  if (parsed.isIp)
    throw new InvalidDomainError(
      'IP addresses cannot be monitored; enter a domain name',
    );
  if (!parsed.domain || !parsed.publicSuffix || !parsed.isIcann) {
    throw new InvalidDomainError(
      `"${input}" has no registrable domain under a known public suffix`,
    );
  }
  return { ascii, unicode: domainToUnicode(ascii), registrable: parsed.domain };
}
