import { Injectable } from '@nestjs/common';
import { getDomain } from 'tldts';
import { WhoisSource } from '../../../database/generated/prisma/enums.js';
import { RdapClient } from './rdap.client.js';
import { Whois43Client } from './whois43.client.js';
import { parseWhois } from './whois-parser.js';
import {
  RAW_TEXT_LIMIT,
  type WhoisLookupResult,
  type WhoisRecord,
} from './whois.types.js';

export class WhoisUnavailableError extends Error {}

const hasData = (r: WhoisRecord) =>
  Boolean(
    r.registrar ||
    r.createdDate ||
    r.expiresDate ||
    r.nameServers.length ||
    r.registrantOrg,
  );

/** RDAP first (structured, rate-limit friendly), port-43 WHOIS as the fallback. */
@Injectable()
export class WhoisLookupService {
  constructor(
    private readonly rdap: RdapClient,
    private readonly whois43: Whois43Client,
  ) {}

  /**
   * Returns registration data for the look-alike's registrable domain. Throws
   * WhoisUnavailableError only for transient failures (so the job retries); a definitive
   * "not registered" answer is returned with parseSucceeded=false.
   */
  async lookup(domain: string): Promise<WhoisLookupResult> {
    const registrable = getDomain(domain) ?? domain;
    const failures: string[] = [];

    const rdap = await this.rdap.lookup(registrable);
    if (rdap.kind === 'found') {
      return {
        source: WhoisSource.RDAP,
        queriedDomain: registrable,
        record: rdap.record,
        rawText: rdap.raw.slice(0, RAW_TEXT_LIMIT),
        parseSucceeded: hasData(rdap.record),
      };
    }
    if (rdap.kind === 'error') failures.push(rdap.message);

    const port43 = await this.whois43.lookup(registrable);
    if (port43.kind === 'found' || port43.kind === 'not_found') {
      const parsed = parseWhois(port43.text);
      const record: WhoisRecord = {
        registrar: parsed.registrar,
        registrantOrg: parsed.org,
        registrantCountry: parsed.country,
        emails: (parsed.emails ?? []).map((e) => e.toLowerCase()),
        abuseEmail: parsed.emails?.find((e) => /abuse/i.test(e))?.toLowerCase(),
        nameServers: parsed.nameServers ?? [],
        statuses: parsed.status ?? [],
        dnssec: parsed.dnssec,
        whoisServer: parsed.whoisServer ?? port43.server,
        createdDate: parsed.creationDate,
        updatedDate: parsed.updatedDate,
        expiresDate: parsed.expirationDate,
      };
      return {
        source: WhoisSource.WHOIS,
        queriedDomain: registrable,
        record,
        rawText: port43.text.slice(0, RAW_TEXT_LIMIT),
        parseSucceeded: port43.kind === 'found' && hasData(record),
      };
    }
    failures.push(
      port43.kind === 'rate_limited'
        ? `WHOIS ${port43.server} rate-limited`
        : port43.message,
    );

    if (rdap.kind === 'not_found') {
      // RDAP said 404 and port 43 couldn't answer: record the definitive RDAP answer.
      return {
        source: WhoisSource.RDAP,
        queriedDomain: registrable,
        record: { emails: [], nameServers: [], statuses: [] },
        rawText: 'RDAP: 404 Not Found',
        parseSucceeded: false,
      };
    }
    throw new WhoisUnavailableError(failures.join('; '));
  }
}
