import { Injectable } from '@nestjs/common';
import { TransactionalEventBus } from '../../common/events/transactional-event-bus.js';
import type { WhoisInformationModel } from '../../database/generated/prisma/models.js';
import {
  WhoisInformationBeforeCreateEvent,
  WhoisInformationCreatedEvent,
} from './events/whois-information.events.js';
import type { WhoisLookupResult } from './lookup/whois.types.js';

/** Writes WHOIS/RDAP snapshots (append-only). */
@Injectable()
export class WhoisInformationsService {
  constructor(private readonly bus: TransactionalEventBus) {}

  create(
    scannedDomainId: string,
    result: WhoisLookupResult,
    scanId?: string,
  ): Promise<WhoisInformationModel> {
    const { record } = result;
    return this.bus.write({
      before: new WhoisInformationBeforeCreateEvent(
        scannedDomainId,
        result.source,
      ),
      work: async (tx, after) => {
        const row = await tx.whoisInformation.create({
          data: {
            scannedDomainId,
            source: result.source,
            registrar: record.registrar?.slice(0, 500),
            registrantOrg: record.registrantOrg?.slice(0, 500),
            registrantCountry: record.registrantCountry?.slice(0, 100),
            abuseEmail: record.abuseEmail?.slice(0, 320),
            emails: record.emails.slice(0, 50),
            nameServers: record.nameServers.slice(0, 50),
            statuses: record.statuses.slice(0, 50),
            dnssec: record.dnssec?.slice(0, 100),
            whoisServer: record.whoisServer?.slice(0, 253),
            createdDate: record.createdDate,
            updatedDate: record.updatedDate,
            expiresDate: record.expiresDate,
            rawText: result.rawText,
            parseSucceeded: result.parseSucceeded,
          },
        });
        after.add(
          new WhoisInformationCreatedEvent(
            row.id,
            scannedDomainId,
            scanId,
            result.parseSucceeded,
          ),
        );
        return row;
      },
    });
  }
}
