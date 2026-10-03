import { type DynamicModule, Module, type Provider } from '@nestjs/common';
import { ThreatFeedModule } from '../integrations/threat-feed/threat-feed.module.js';
import { QUEUES, type QueueName } from '../queue/queue.constants.js';
import { AnalyticsModule } from './analytics/analytics.module.js';
import { AnalyticsProcessor } from './analytics/processors/analytics.processor.js';
import { DnsResolverModule } from './dns-resolver/dns-resolver.module.js';
import { DomainRescanProcessor } from './scanned-domains/processors/domain-rescan.processor.js';
import { RulesModule } from './rules/rules.module.js';
import { ScannedDomainsModule } from './scanned-domains/scanned-domains.module.js';
import { ScreenshotProcessor } from './screenshots/processors/screenshot.processor.js';
import { BrandReferenceScheduler } from './screenshots/listeners/brand-reference.listener.js';
import { ScreenshotsModule } from './screenshots/screenshots.module.js';
import { ThreatFeedPushProcessor } from './threat-feed-sync/processors/threat-feed-push.processor.js';
import { ThreatFeedSyncModule } from './threat-feed-sync/threat-feed-sync.module.js';
import { WhoisProcessor } from './whois-informations/processors/whois.processor.js';
import { WhoisInformationsModule } from './whois-informations/whois-informations.module.js';

export const ENRICHMENT_PROCESSORS: Partial<Record<QueueName, Provider>> = {
  [QUEUES.WHOIS]: WhoisProcessor,
  [QUEUES.SCREENSHOT]: ScreenshotProcessor,
  [QUEUES.ANALYTICS]: AnalyticsProcessor,
  [QUEUES.DOMAIN_RESCAN]: DomainRescanProcessor,
  [QUEUES.THREAT_FEED_PUSH]: ThreatFeedPushProcessor,
};

/**
 * Enrichment processors (WHOIS, screenshots, scoring). The modules are always imported so
 * their event listeners run in the worker that emits `scanned-domain.*` events; only the
 * processors are filtered by WORKER_QUEUES.
 */
@Module({})
export class EnrichmentWorkerModule {
  static forQueues(queues: readonly string[]): DynamicModule {
    return {
      module: EnrichmentWorkerModule,
      imports: [
        ScannedDomainsModule,
        WhoisInformationsModule,
        ScreenshotsModule,
        RulesModule,
        AnalyticsModule,
        ThreatFeedSyncModule,
        // Direct dependencies of the rescan and threat-feed push processors.
        DnsResolverModule,
        ThreatFeedModule,
      ],
      providers: [
        ...Object.entries(ENRICHMENT_PROCESSORS)
          .filter(([queue]) => queues.length === 0 || queues.includes(queue))
          .map(([, provider]) => provider!),
        // Weekly brand-reference refresh runs on the screenshot queue.
        ...(queues.length === 0 || queues.includes(QUEUES.SCREENSHOT)
          ? [BrandReferenceScheduler]
          : []),
      ],
    };
  }
}
