import { OnWorkerEvent, Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import type { Job } from 'bullmq';
import { withJobContext } from '../../../common/utils/job-context.js';
import { ScanStatus } from '../../../database/generated/prisma/enums.js';
import type { FinalizeJobData } from '../../../queue/jobs.js';
import { QUEUES } from '../../../queue/queue.constants.js';
import { ScannedDomainsQuery } from '../../scanned-domains/scanned-domains.query.js';
import { ScansService } from '../scans.service.js';

/** Size of DNS batch `index` (the last batch may be partial). */
export function batchSizeAt(
  index: number,
  batchSize: number,
  total: number,
): number {
  return Math.max(0, Math.min(batchSize, total - index * batchSize));
}

/**
 * Flow parent: runs once every DNS batch has finished (or exhausted its retries).
 * Totals come from the rows themselves, so they are exact even if events were retried.
 */
@Processor(QUEUES.SCAN_FINALIZE, { concurrency: 2 })
export class ScanFinalizeProcessor extends WorkerHost {
  private readonly logger = new Logger(ScanFinalizeProcessor.name);

  constructor(
    private readonly scans: ScansService,
    private readonly scannedDomains: ScannedDomainsQuery,
  ) {
    super();
  }

  process(job: Job<FinalizeJobData>) {
    return withJobContext(job, job.data.scanId, () => this.run(job));
  }

  private async run(job: Job<FinalizeJobData>) {
    const { scanId, batchSize, permutationsTotal } = job.data;
    const scan = await this.scans.get(scanId);
    if (scan.status !== ScanStatus.RESOLVING)
      return { skipped: `scan is ${scan.status}` };

    const failures = await job.getIgnoredChildrenFailures();
    const failedBatches = Object.keys(failures).map((key) =>
      Number(key.split('-').pop()),
    );
    const failedCount = failedBatches.reduce(
      (n, i) => n + batchSizeAt(i, batchSize, permutationsTotal),
      0,
    );
    const totalBatches = Math.ceil(permutationsTotal / batchSize);

    if (totalBatches > 0 && failedBatches.length === totalBatches) {
      await this.scans.fail(
        scanId,
        `All ${totalBatches} DNS batches failed: ${Object.values(failures)[0] ?? 'unknown error'}`,
      );
      return { status: ScanStatus.FAILED };
    }

    const counts = await this.scannedDomains.countsForScan(
      scanId,
      scan.startedAt,
    );
    await this.scans.complete(scanId, { ...counts, failedCount });
    this.logger.log(
      `Scan ${scanId} completed: ${counts.registeredCount} registered (${counts.newCount} new), ${failedCount} unresolved`,
    );
    return { status: ScanStatus.COMPLETED, ...counts, failedCount };
  }

  @OnWorkerEvent('failed')
  async onFailed(job: Job<FinalizeJobData>, error: Error): Promise<void> {
    if (job.attemptsMade < (job.opts.attempts ?? 1)) return;
    await this.scans
      .fail(job.data.scanId, `Finalisation failed: ${error.message}`)
      .catch(() => undefined);
  }
}
