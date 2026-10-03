import { ScreenshotsModule } from '../screenshots/screenshots.module.js';
import { Module } from '@nestjs/common';
import { RulesModule } from '../rules/rules.module.js';
import { ScannedDomainsModule } from '../scanned-domains/scanned-domains.module.js';
import { WhoisInformationsModule } from '../whois-informations/whois-informations.module.js';
import { AnalyticsController } from './analytics.controller.js';
import { AnalyticsEnqueuer } from './analytics.enqueuer.js';
import { AnalyticsQuery } from './analytics.query.js';
import { AnalyticsService } from './analytics.service.js';
import { AnalyticsTriggerListener } from './listeners/analytics-trigger.listener.js';

@Module({
  imports: [
    ScannedDomainsModule,
    WhoisInformationsModule,
    RulesModule,
    ScreenshotsModule,
  ],
  controllers: [AnalyticsController],
  providers: [
    AnalyticsService,
    AnalyticsQuery,
    AnalyticsEnqueuer,
    AnalyticsTriggerListener,
  ],
  exports: [AnalyticsService],
})
export class AnalyticsModule {}
