import { Module } from '@nestjs/common';
import { ScannedDomainsModule } from '../scanned-domains/scanned-domains.module.js';
import { WhoisTriggerListener } from './listeners/whois-trigger.listener.js';
import { RdapClient } from './lookup/rdap.client.js';
import { Whois43Client } from './lookup/whois43.client.js';
import { WhoisLookupService } from './lookup/whois-lookup.service.js';
import { WhoisEnqueuer } from './whois.enqueuer.js';
import { WhoisInformationsController } from './whois-informations.controller.js';
import { WhoisInformationsQuery } from './whois-informations.query.js';
import { WhoisInformationsService } from './whois-informations.service.js';

@Module({
  imports: [ScannedDomainsModule],
  controllers: [WhoisInformationsController],
  providers: [
    WhoisInformationsService,
    WhoisInformationsQuery,
    WhoisEnqueuer,
    WhoisTriggerListener,
    RdapClient,
    Whois43Client,
    WhoisLookupService,
  ],
  exports: [
    WhoisInformationsQuery,
    WhoisInformationsService,
    WhoisLookupService,
  ],
})
export class WhoisInformationsModule {}
