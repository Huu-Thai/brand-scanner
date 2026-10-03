import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import type { Job } from 'bullmq';
import { withJobContext } from '../../../common/utils/job-context.js';
import { JOBS, type RetentionJobData } from '../../../queue/jobs.js';
import { QUEUES } from '../../../queue/queue.constants.js';
import { RetentionService } from '../retention.service.js';

/** Runs retention and the orphan sweep (one at a time; the service also holds a Redis lock). */
@Processor(QUEUES.RETENTION, { concurrency: 1, lockDuration: 300_000 })
export class RetentionProcessor extends WorkerHost {
  private readonly logger = new Logger(RetentionProcessor.name);

  constructor(private readonly retention: RetentionService) {
    super();
  }

  process(job: Job<RetentionJobData>) {
    return withJobContext(job, undefined, async () => {
      const report =
        job.name === JOBS.ORPHAN_SWEEP
          ? await this.retention.sweepOrphans(job.data.requestedBy)
          : await this.retention.run(job.data.requestedBy);
      if (!report) {
        this.logger.warn(`${job.name} skipped: another run is in progress`);
        return { skipped: 'already running' };
      }
      return report;
    });
  }
}
