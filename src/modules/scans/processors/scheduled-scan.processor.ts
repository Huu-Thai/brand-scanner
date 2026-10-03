import { Processor, WorkerHost } from '@nestjs/bullmq';
import { HttpException, Logger } from '@nestjs/common';
import type { Job } from 'bullmq';
import { withJobContext } from '../../../common/utils/job-context.js';
import { ScanTrigger } from '../../../database/generated/prisma/enums.js';
import type { ScheduledScanJobData } from '../../../queue/jobs.js';
import { QUEUES } from '../../../queue/queue.constants.js';
import { ScansService } from '../scans.service.js';

/** Fired by the per-domain job scheduler; starts a SCHEDULE-triggered scan. */
@Processor(QUEUES.SCHEDULER, { concurrency: 1 })
export class ScheduledScanProcessor extends WorkerHost {
  private readonly logger = new Logger(ScheduledScanProcessor.name);

  constructor(private readonly scans: ScansService) {
    super();
  }

  process(job: Job<ScheduledScanJobData>) {
    return withJobContext(job, undefined, async () => {
      try {
        const { scan, created } = await this.scans.create({
          originalDomainId: job.data.originalDomainId,
          triggeredBy: ScanTrigger.SCHEDULE,
        });
        if (!created)
          this.logger.log(
            `Skipped scheduled scan: scan ${scan.id} still ${scan.status}`,
          );
        return { scanId: scan.id, created };
      } catch (e) {
        // Deleted / deactivated domain whose scheduler hasn't been reconciled yet — not retryable.
        if (e instanceof HttpException && e.getStatus() < 500) {
          this.logger.warn(
            `Scheduled scan skipped for ${job.data.originalDomainId}: ${e.message}`,
          );
          return { skipped: e.message };
        }
        throw e;
      }
    });
  }
}
