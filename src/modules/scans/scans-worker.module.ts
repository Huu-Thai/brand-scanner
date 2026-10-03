import { type DynamicModule, Module, type Provider } from '@nestjs/common';
import { QUEUES, type QueueName } from '../../queue/queue.constants.js';
import { DnsResolverModule } from '../dns-resolver/dns-resolver.module.js';
import { FuzzerModule } from '../fuzzer/fuzzer.module.js';
import { OriginalDomainsModule } from '../original-domains/original-domains.module.js';
import { ScannedDomainsModule } from '../scanned-domains/scanned-domains.module.js';
import { DnsResolveProcessor } from './processors/dns-resolve.processor.js';
import { ScanFinalizeProcessor } from './processors/scan-finalize.processor.js';
import { ScanOrchestratorProcessor } from './processors/scan-orchestrator.processor.js';
import { ScheduledScanProcessor } from './processors/scheduled-scan.processor.js';
import { ScansModule } from './scans.module.js';

export const SCAN_PROCESSORS: Partial<Record<QueueName, Provider>> = {
  [QUEUES.SCAN_ORCHESTRATOR]: ScanOrchestratorProcessor,
  [QUEUES.DNS_RESOLVE]: DnsResolveProcessor,
  [QUEUES.SCAN_FINALIZE]: ScanFinalizeProcessor,
  [QUEUES.SCHEDULER]: ScheduledScanProcessor,
};

/** Registers only the processors for the queues this worker serves (WORKER_QUEUES; empty = all). */
@Module({})
export class ScansWorkerModule {
  static forQueues(queues: readonly string[]): DynamicModule {
    const selected = Object.entries(SCAN_PROCESSORS)
      .filter(([queue]) => queues.length === 0 || queues.includes(queue))
      .map(([, provider]) => provider!);
    return {
      module: ScansWorkerModule,
      imports: [
        ScansModule,
        OriginalDomainsModule,
        ScannedDomainsModule,
        FuzzerModule,
        DnsResolverModule,
      ],
      providers: selected,
    };
  }
}
