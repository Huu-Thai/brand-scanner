import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import type { Job } from 'bullmq';
import { withJobContext } from '../../../common/utils/job-context.js';
import { ScanStatus } from '../../../database/generated/prisma/enums.js';
import type { ResolveJobData } from '../../../queue/jobs.js';
import { QUEUES } from '../../../queue/queue.constants.js';
import { DnsResolverService } from '../../dns-resolver/dns-resolver.service.js';
import {
  enrichmentFlags,
  SCAN_EVENTS,
  ScanBatchResolvedEvent,
  type ScanOptions,
} from '../events/scan.events.js';
import { ScansService } from '../scans.service.js';

/**
 * Resolves one batch and hands the results to the scanned-domains module through an
 * awaited event (emitAsync), so persistence failures fail — and retry — this job.
 */
@Processor(QUEUES.DNS_RESOLVE, { concurrency: 4 })
export class DnsResolveProcessor extends WorkerHost {
  private readonly logger = new Logger(DnsResolveProcessor.name);

  constructor(
    private readonly dns: DnsResolverService,
    private readonly scans: ScansService,
    private readonly events: EventEmitter2,
  ) {
    super();
  }

  process(job: Job<ResolveJobData>) {
    return withJobContext(job, job.data.scanId, () => this.run(job));
  }

  private async run(job: Job<ResolveJobData>) {
    const { scanId, originalDomainId, permutations, batchIndex } = job.data;
    const scan = await this.scans.get(scanId);
    if (scan.status !== ScanStatus.RESOLVING)
      return { skipped: `scan is ${scan.status}` };

    const started = Date.now();
    const resolutions = await this.dns.resolveMany(
      permutations.map(([domain]) => domain),
    );
    const registered = resolutions.filter((r) => r.registered);

    await this.events.emitAsync(
      SCAN_EVENTS.BATCH_RESOLVED,
      new ScanBatchResolvedEvent(
        scanId,
        originalDomainId,
        Object.fromEntries(permutations),
        registered,
        enrichmentFlags(scan.options as ScanOptions),
      ),
    );
    // Progress is only counted once, on the attempt that succeeded.
    await this.scans.recordProgress(scanId, permutations.length);

    this.logger.debug(
      `Batch ${batchIndex}: ${registered.length}/${permutations.length} registered in ${Date.now() - started}ms`,
    );
    return { resolved: permutations.length, registered: registered.length };
  }
}
