import { Module } from '@nestjs/common';
import { ScanPipelineListener } from './listeners/scan-pipeline.listener.js';
import { StatusRulesListener } from './listeners/status-rules.listener.js';
import { RescanEnqueuer } from './rescan.enqueuer.js';
import { ScannedDomainsExportService } from './scanned-domains.export.js';
import { ScannedDomainsController } from './scanned-domains.controller.js';
import { ScannedDomainsQuery } from './scanned-domains.query.js';
import { ScannedDomainsReadService } from './scanned-domains.read.service.js';
import { ScannedDomainsService } from './scanned-domains.service.js';

@Module({
  controllers: [ScannedDomainsController],
  providers: [
    ScannedDomainsService,
    ScannedDomainsReadService,
    ScannedDomainsQuery,
    ScanPipelineListener,
    StatusRulesListener,
    ScannedDomainsExportService,
    RescanEnqueuer,
  ],
  exports: [ScannedDomainsQuery, ScannedDomainsService],
})
export class ScannedDomainsModule {}
