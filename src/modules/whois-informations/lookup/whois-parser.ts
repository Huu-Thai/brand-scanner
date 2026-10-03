/**
 * WHOIS text parser — ported verbatim from Reporting
 * `src/modules/wsd-scanner-worker/utils/whois-parser.util.ts` (itself a port of the Python
 * WSD_Worker_API whois_run.py extractor). Handles many registry-specific field variants and
 * date formats; keep changes deliberate and covered by whois-parser.spec.ts.
 */
export interface ParsedWhois {
  registrar?: string;
  whoisServer?: string;
  serverName?: string;
  creationDate?: Date;
  updatedDate?: Date;
  expirationDate?: Date;
  address?: string;
  city?: string;
  state?: string;
  zipcode?: string;
  country?: string;
  org?: string;
  name?: string;
  adminName?: string;
  phone?: string;
  emails?: string[];
  status?: string[];
  nameServers?: string[];
  dnssec?: string;
}

// ─── Date parsing (mirrors Python _brute_datetime()) ─────────────────────────

const MONTH_MAP: Record<string, number> = {
  jan: 1,
  feb: 2,
  mar: 3,
  apr: 4,
  may: 5,
  jun: 6,
  jul: 7,
  aug: 8,
  sep: 9,
  oct: 10,
  nov: 11,
  dec: 12,
  january: 1,
  february: 2,
  march: 3,
  april: 4,
  june: 6,
  july: 7,
  august: 8,
  september: 9,
  october: 10,
  november: 11,
  december: 12,
};

const TZ_REPLACEMENTS: Record<string, string> = {
  CLST: '-03:00',
  CLT: '-04:00',
  EST: '-05:00',
  CST: '-06:00',
  MST: '-07:00',
  PST: '-08:00',
  AKST: '-09:00',
  HAST: '-10:00',
  JST: '+09:00',
  AEDT: '+11:00',
  AEST: '+10:00',
};

export function parseWhoisDate(raw: string): Date | undefined {
  let s = raw.trim();
  if (!s) return undefined;

  // Replace named timezone abbreviations (strip leading whitespace so offset
  // attaches directly to the time — "T10:00:00 JST" → "T10:00:00+09:00")
  for (const [tz, offset] of Object.entries(TZ_REPLACEMENTS)) {
    s = s.replace(new RegExp(`\\s+${tz}\\b`, 'g'), offset);
  }

  // Remove parenthetical timezone (e.g. "(JST)")
  s = s.replace(/\([A-Z]{3,4}\)/g, '').trim();

  // Remove ordinal suffixes: 1st → 1, 2nd → 2, etc.
  s = s.replace(/(\d+)(st|nd|rd|th)\b/g, '$1');

  // Compact YYYYMMDD
  if (/^\d{8}$/.test(s)) {
    const year = parseInt(s.slice(0, 4), 10);
    const month = parseInt(s.slice(4, 6), 10);
    const day = parseInt(s.slice(6, 8), 10);
    const d = new Date(Date.UTC(year, month - 1, day));
    if (!isNaN(d.getTime())) return d;
  }

  // YYYY.MM.DD HH:MM:SS or YYYY.MM.DD HH:MM — must come before simple dotted check
  const dottedFull = s.match(
    /^(\d{4})\.(\d{1,2})\.(\d{1,2})\s+(\d{2}):(\d{2})/,
  );
  if (dottedFull) {
    const d = new Date(
      Date.UTC(
        +dottedFull[1],
        +dottedFull[2] - 1,
        +dottedFull[3],
        +dottedFull[4],
        +dottedFull[5],
      ),
    );
    if (!isNaN(d.getTime())) return d;
  }

  // Try native Date() only for ISO 8601 (contains T) or plain YYYY-MM-DD (spec-guaranteed UTC).
  // Other formats like YYYY.MM.DD or DD-Mon-YYYY are parsed as local time by V8, giving wrong UTC values.
  if (s.includes('T') || /^\d{4}-\d{2}-\d{2}$/.test(s)) {
    const nativeAttempt = new Date(s);
    if (!isNaN(nativeAttempt.getTime())) return nativeAttempt;
  }

  // Dotted date: 2025.01.05
  const dotted = s.match(/^(\d{4})\.(\d{1,2})\.(\d{1,2})/);
  if (dotted) {
    const d = new Date(Date.UTC(+dotted[1], +dotted[2] - 1, +dotted[3]));
    if (!isNaN(d.getTime())) return d;
  }

  // DD.MM.YYYY or DD.MM.YYYY HH:MM:SS
  const ddmmyyyy = s.match(/^(\d{1,2})\.(\d{1,2})\.(\d{4})/);
  if (ddmmyyyy) {
    const d = new Date(Date.UTC(+ddmmyyyy[3], +ddmmyyyy[2] - 1, +ddmmyyyy[1]));
    if (!isNaN(d.getTime())) return d;
  }

  // DD/MM/YYYY
  const slashed = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if (slashed) {
    const d = new Date(Date.UTC(+slashed[3], +slashed[2] - 1, +slashed[1]));
    if (!isNaN(d.getTime())) return d;
  }

  // DD-Mon-YYYY or DD Mon YYYY (e.g. 05-Jan-2025, 05 Jan 2025, 5 January 2025)
  const namedMonth = s.match(/^(\d{1,2})[-\s]+([A-Za-z]{3,9})[-\s]+(\d{4})/);
  if (namedMonth) {
    const month = MONTH_MAP[namedMonth[2].toLowerCase()];
    if (month) {
      const d = new Date(Date.UTC(+namedMonth[3], month - 1, +namedMonth[1]));
      if (!isNaN(d.getTime())) return d;
    }
  }

  // YYYY-Mon-DD (e.g. 2025-Jan-05)
  const yearNamedMonth = s.match(/^(\d{4})-([A-Za-z]{3,9})-(\d{1,2})/);
  if (yearNamedMonth) {
    const month = MONTH_MAP[yearNamedMonth[2].toLowerCase()];
    if (month) {
      const d = new Date(
        Date.UTC(+yearNamedMonth[1], month - 1, +yearNamedMonth[3]),
      );
      if (!isNaN(d.getTime())) return d;
    }
  }

  // Mon DD YYYY or Month DD YYYY (e.g. Jan 05 2025, January 05 2025)
  const monthFirst = s.match(/^([A-Za-z]{3,9})\s+(\d{1,2})\s+(\d{4})/);
  if (monthFirst) {
    const month = MONTH_MAP[monthFirst[1].toLowerCase()];
    if (month) {
      const d = new Date(Date.UTC(+monthFirst[3], month - 1, +monthFirst[2]));
      if (!isNaN(d.getTime())) return d;
    }
  }

  return undefined;
}

// ─── Field extraction ─────────────────────────────────────────────────────────

// Each entry: [fieldName, regex]. First match wins.
const SINGLE_PATTERNS: Array<[keyof ParsedWhois, RegExp]> = [
  [
    'registrar',
    // Use `:` as separator, or `.name:`/` name:` for formats like "Registrar.Name: value" or
    // "Registrar Name: value" (e.g. .ae). Do NOT use `[:.]` — a bare `.` matches wrapped NOTICE
    // lines like "registrar.  Users may consult..."; requiring the literal "name" keyword after
    // the dot/space also keeps this from matching unrelated fields like "Registrar ID:".
    /^(?:registrar|registering agency|registration service provider|sponsor|provider)\s*(?::\s*(?:name\s*:)?\s*|[.\s]+name\s*:\s*)(.+)/im,
  ],
  [
    'whoisServer',
    /^(?:registrar whois server|whois server|referral url|whois lookup server)\s*[:.]\s*(.+)/im,
  ],
  [
    'creationDate',
    // `[:.]+` (not `[:.]`) so dot-leader formats like "Created on..............: 2017-Jun-01" (.tr/TRABIS) parse too.
    /^(?:(?:creation date|created(?: on)?|registered(?: on)?|registration date|domain created|domain registered|domain registration date|created on|domain creation date|first registered)\s*[:.]+\s*|\[created on\]\s+)(.+)/im,
  ],
  [
    'updatedDate',
    /^(?:updated date|last update(?:d)?|last modified|modification date|modified|last[\s-]changed|changed|update date)\s*[:.]\s*(.+)/im,
  ],
  [
    'expirationDate',
    // `[:.]+` (not `[:.]`) so dot-leader formats like "Expires on..............: 2027-May-31" (.tr/TRABIS) parse too.
    /^(?:(?:registry expiry date|expir(?:ation|y)(?: date)?|expire(?:s)?(?:(?: on)?)?|renewal date|paid-till|valid until|expiry|expiration|registrar registration expiration date|domain expiration date)\s*[:.]+\s*|\[expires on\]\s+)(.+)/im,
  ],
  [
    'address',
    // Bare "Address:" (no registrant/owner/admin prefix) covers registries like .tr/TRABIS
    // that print contact fields directly under a "** Registrar:" section header.
    /^(?:(?:registrant|owner|admin)[\s.]?(?:street|address(?:1)?|street1)|address)\s*[:.]\s*(.+)/im,
  ],
  ['city', /^(?:registrant|owner|admin)[\s.]?city\s*[:.]\s*(.+)/im],
  [
    'state',
    /^(?:registrant|owner|admin)[\s.]?(?:state|province)(?:\/province)?\s*[:.]\s*(.+)/im,
  ],
  [
    'zipcode',
    /^(?:registrant|owner|admin)[\s.]?(?:postal[\s-]?code|zip\s?code|postcode)\s*[:.]\s*(.+)/im,
  ],
  [
    'country',
    /^(?:registrant|owner|admin)[\s.]?country(?:[\s-]?code)?\s*[:.]\s*(.+)/im,
  ],
  [
    'org',
    // Third branch: bare "Organization/Organisation Name:" (no registrant/owner prefix) covers
    // registries like .tr/TRABIS that print it directly under a "** Registrar:" section header.
    /^(?:registrant|owner)[\s.]?org(?:anization)?\s*[:.]\s*(.+)|^organisation\s*[:.]\s*(.+)|^organi[sz]ation name\s*[:.]\s*(.+)/im,
  ],
  [
    'name',
    /^(?:(?:registrant|owner)(?:[\s.]name)?|domain\s+holder|domain\s+owner|holder)\s*[:.]\s*(.+)/im,
  ],
  [
    'adminName',
    /^(?:admin name|administrative contact(?:\s+name)?)\s*[:.]\s*(.+)/im,
  ],
  [
    'phone',
    // Bare "Phone:" (no registrant/owner prefix) covers registries like .tr/TRABIS that
    // print contact fields directly under a "** Registrar:" section header.
    /^(?:(?:registrant|owner)[\s.]?(?:phone|telephone|voice)|phone)\s*[:.]\s*(.+)/im,
  ],
  ['serverName', /^(?:registrar|registry)\s+server\s+name\s*[:.]\s*(.+)/im],
  ['dnssec', /^dnssec\s*[:.]\s*(.+)/im],
];

function extractLineValue(output: string, pattern: RegExp): string | undefined {
  // Run against each line to avoid cross-line matches
  for (const line of output.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith('%')) continue;
    const m = trimmed.match(pattern);
    if (m) {
      // Handle patterns with multiple capture groups (org has two)
      for (let i = 1; i < m.length; i++) {
        if (m[i]?.trim()) return m[i].trim();
      }
    }
  }
  return undefined;
}

/**
 * Parse raw WHOIS text into structured fields.
 * Handles many registry-specific field name variants (RDAP, ccTLD, legacy formats).
 */
export function parseWhois(output: string): ParsedWhois {
  const result: ParsedWhois = {};

  for (const [field, pattern] of SINGLE_PATTERNS) {
    const value = extractLineValue(output, pattern);
    if (!value) continue;

    if (
      field === 'creationDate' ||
      field === 'updatedDate' ||
      field === 'expirationDate'
    ) {
      const parsed = parseWhoisDate(value);
      if (parsed) (result as Record<string, unknown>)[field] = parsed;
    } else {
      (result as Record<string, unknown>)[field] = value;
    }
  }

  // Emails — scan whole body
  const emailMatches = output.match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi);
  if (emailMatches) result.emails = [...new Set(emailMatches)];

  // Status — multiple lines
  const statuses: string[] = [];
  for (const m of output.matchAll(/^(?:domain )?status\s*[:.]?\s*(.+)/gim)) {
    const v = m[1].trim();
    if (v) statuses.push(v);
  }
  if (statuses.length > 0) result.status = [...new Set(statuses)];

  // Name servers — multiple lines, many variants. "ns" requires a mandatory separator (unlike
  // the other keywords) since it's also the literal start of hostnames like "ns1.example.com" —
  // an optional separator would eat that "ns" prefix and capture "1.example.com" instead.
  const NS_LABEL_PATTERN =
    /^(?:(?:name\s*server|nserver|nameserver|hostname)\s*[:.]?\s*|ns\s*[:.]\s*)(.+)/i;
  // Some registries (e.g. .tr/TRABIS) list nameservers as bare hostnames with no label at all,
  // one per line under a "Domain Servers:" section header.
  const BARE_HOSTNAME_PATTERN =
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i;

  const nsLines: string[] = [];
  for (const rawLine of output.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('%')) continue;

    const labeled = line.match(NS_LABEL_PATTERN);
    const candidate = labeled
      ? labeled[1].split(/\s+/)[0]
      : BARE_HOSTNAME_PATTERN.test(line)
        ? line
        : undefined;

    const host = candidate?.toLowerCase().trim();
    if (host && host.includes('.') && !/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      nsLines.push(host);
    }
  }
  if (nsLines.length > 0) result.nameServers = [...new Set(nsLines)];

  return result;
}
