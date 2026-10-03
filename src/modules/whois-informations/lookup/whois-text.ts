/**
 * Response classification for raw port-43 WHOIS text, ported from Reporting's
 * WhoisQueryService (isRateLimited / isDomainNotFound / isValidDomainResponse) and
 * change-detection.util (hasWhoisData).
 */

/** Registry-side throttling embedded in the text (port 43 has no status codes). */
export function isRateLimited(text: string): boolean {
  const lower = text.toLowerCase();
  return (
    /\b429\b/.test(text) ||
    lower.includes('too many requests') ||
    lower.includes('access quota') ||
    (lower.includes('quota') && lower.includes('exceed'))
  );
}

/** A definitive "not registered here" answer — never worth retrying. */
export function isDomainNotFound(text: string): boolean {
  const lower = text.toLowerCase();
  return (
    lower.includes('no match for') ||
    lower.includes('no entries found') ||
    lower.includes('not found') ||
    lower.includes('no data found')
  );
}

const UNREGISTERED_INDICATORS = [
  'domain not found',
  'object does not exist',
  'no match found',
  'available for registration',
  'status: available',
];

const POSITIVE_INDICATORS = [
  'registrar:',
  'registrar id:',
  'registrar name:',
  'creation date:',
  'created:',
  'registered:',
  'registry expiry:',
  'expires:',
  'expiry date:',
  'status: ok',
  'status: active',
  'registrant:',
  'registrant contact',
  'admin contact:',
  'admin contact id',
  'tech contact:',
  'tech contact id',
  'name server:',
  'nserver:',
];

/** Looks like real registration data — not an "available" answer, IANA stub or short error. */
export function hasWhoisData(text: string): boolean {
  const normalized = text.toLowerCase().replace(/[ \t]+/g, ' ');
  if (UNREGISTERED_INDICATORS.some((i) => normalized.includes(i))) return false;
  return POSITIVE_INDICATORS.some((indicator) =>
    normalized.includes(indicator),
  );
}

export function isValidDomainResponse(text: string): boolean {
  const lower = text.toLowerCase();
  return (
    (text.trim().length > 50 &&
      !lower.includes('% iana whois server') &&
      !lower.includes('source:       iana')) ||
    hasWhoisData(text)
  );
}

/** "Registrar WHOIS Server: whois.registrar.example" — thin registries (.com/.net) refer to the thick record. */
export function registrarReferral(text: string): string | undefined {
  const m = text.match(
    /^\s*registrar whois server\s*:\s*(?:whois:\/\/)?([a-z0-9.-]+\.[a-z]{2,})\s*$/im,
  );
  return m?.[1].toLowerCase();
}
