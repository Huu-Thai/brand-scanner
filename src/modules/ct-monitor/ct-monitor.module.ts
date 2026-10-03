import { type DynamicModule, Module } from '@nestjs/common';
import { QUEUES } from '../../queue/queue.constants.js';
import { DnsResolverModule } from '../dns-resolver/dns-resolver.module.js';
import { OriginalDomainsModule } from '../original-domains/original-domains.module.js';
import { ScannedDomainsModule } from '../scanned-domains/scanned-domains.module.js';
import { CtMonitorController } from './ct-monitor.controller.js';
import { CtStreamService } from './ct-stream.service.js';
import { CtMatchProcessor } from './processors/ct-match.processor.js';

/** API side: status endpoint. */
@Module({ controllers: [CtMonitorController] })
export class CtMonitorModule {}

/**
 * Worker side (PLAN §14 #1): the stream consumer and the match processor run where the
 * `ct-matches` queue is served; leader election keeps a single consumer across replicas.
 */
@Module({})
export class CtMonitorWorkerModule {
  static forQueues(queues: readonly string[]): DynamicModule {
    const serve = queues.length === 0 || queues.includes(QUEUES.CT_MATCHES);
    return {
      module: CtMonitorWorkerModule,
      imports: serve
        ? [OriginalDomainsModule, ScannedDomainsModule, DnsResolverModule]
        : [],
      providers: serve ? [CtStreamService, CtMatchProcessor] : [],
    };
  }
}
