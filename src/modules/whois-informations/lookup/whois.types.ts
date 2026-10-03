import type { WhoisSource } from '../../../database/generated/prisma/enums.js';

/** Normalised registration data, from either RDAP JSON or parsed port-43 text. */
export interface WhoisRecord {
  registrar?: string;
  registrantOrg?: string;
  registrantCountry?: string;
  abuseEmail?: string;
  emails: string[];
  nameServers: string[];
  statuses: string[];
  dnssec?: string;
  whoisServer?: string;
  createdDate?: Date;
  updatedDate?: Date;
  expiresDate?: Date;
}

export interface WhoisLookupResult {
  source: WhoisSource;
  /** The queried registrable domain (eTLD+1). */
  queriedDomain: string;
  record: WhoisRecord;
  /** RDAP JSON or WHOIS text, truncated. */
  rawText: string;
  /** False when the registry answered but nothing useful could be extracted. */
  parseSucceeded: boolean;
}

export const RAW_TEXT_LIMIT = 64 * 1024;
