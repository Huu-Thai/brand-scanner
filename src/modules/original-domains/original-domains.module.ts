import { Module } from '@nestjs/common';
import { ScanCompletedListener } from './listeners/scan-completed.listener.js';
import { OriginalDomainsController } from './original-domains.controller.js';
import { OriginalDomainsQuery } from './original-domains.query.js';
import { OriginalDomainsService } from './original-domains.service.js';

@Module({
  controllers: [OriginalDomainsController],
  providers: [
    OriginalDomainsService,
    OriginalDomainsQuery,
    ScanCompletedListener,
  ],
  exports: [OriginalDomainsQuery],
})
export class OriginalDomainsModule {}
