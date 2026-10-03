import type { WhoisRecord } from './whois.types.js';

/** jCard: ["vcard", [[name, params, type, value], …]] */
type VCard = [string, [string, Record<string, unknown>, string, unknown][]];

interface RdapEntity {
  roles?: string[];
  vcardArray?: VCard;
  entities?: RdapEntity[];
  publicIds?: { type: string; identifier: string }[];
}

export interface RdapDomain {
  objectClassName?: string;
  ldhName?: string;
  status?: string[];
  port43?: string;
  events?: { eventAction: string; eventDate: string }[];
  entities?: RdapEntity[];
  nameservers?: { ldhName?: string }[];
  secureDNS?: { delegationSigned?: boolean };
}

function vcardValue(entity: RdapEntity | undefined, field: string): unknown {
  return entity?.vcardArray?.[1]?.find(([name]) => name === field)?.[3];
}

function vcardText(
  entity: RdapEntity | undefined,
  ...fields: string[]
): string | undefined {
  for (const field of fields) {
    const value = vcardValue(entity, field);
    const text = Array.isArray(value) ? value.filter(Boolean).join(' ') : value;
    if (typeof text === 'string' && text.trim()) return text.trim();
  }
  return undefined;
}

function walk(entities: RdapEntity[] | undefined): RdapEntity[] {
  return (entities ?? []).flatMap((e) => [e, ...walk(e.entities)]);
}

const withRole = (entities: RdapEntity[], role: string) =>
  entities.find((e) => e.roles?.map((r) => r.toLowerCase()).includes(role));

function eventDate(domain: RdapDomain, ...actions: string[]): Date | undefined {
  const event = domain.events?.find((e) =>
    actions.includes(e.eventAction.toLowerCase()),
  );
  const date = event ? new Date(event.eventDate) : undefined;
  return date && !Number.isNaN(date.getTime()) ? date : undefined;
}

/** Maps an RDAP domain object (RFC 9083) to the normalised WhoisRecord. */
export function parseRdap(domain: RdapDomain): WhoisRecord {
  const all = walk(domain.entities);
  const registrar = withRole(all, 'registrar');
  const registrant = withRole(all, 'registrant');
  const abuse = withRole(all, 'abuse');

  // adr value: [pobox, ext, street, locality, region, code, country]
  const adr = vcardValue(registrant, 'adr');
  const country =
    Array.isArray(adr) && typeof adr[6] === 'string' && adr[6]
      ? adr[6]
      : undefined;

  const emails = [
    ...new Set(
      all
        .map((e) => vcardText(e, 'email'))
        .filter((e): e is string => Boolean(e) && e!.includes('@'))
        .map((e) => e.toLowerCase()),
    ),
  ];

  return {
    registrar: vcardText(registrar, 'fn', 'org'),
    registrantOrg: vcardText(registrant, 'org', 'fn'),
    registrantCountry: country,
    abuseEmail: vcardText(abuse, 'email')?.toLowerCase(),
    emails,
    nameServers: [
      ...new Set(
        (domain.nameservers ?? [])
          .map((n) => n.ldhName?.toLowerCase())
          .filter((n): n is string => !!n),
      ),
    ],
    statuses: domain.status ?? [],
    dnssec:
      domain.secureDNS?.delegationSigned === undefined
        ? undefined
        : domain.secureDNS.delegationSigned
          ? 'signedDelegation'
          : 'unsigned',
    whoisServer: domain.port43,
    createdDate: eventDate(domain, 'registration'),
    updatedDate: eventDate(
      domain,
      'last changed',
      'last update of rdap database',
    ),
    expiresDate: eventDate(domain, 'expiration'),
  };
}
