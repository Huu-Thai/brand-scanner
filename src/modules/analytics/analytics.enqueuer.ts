import { InjectQueue } from '@nestjs/bullmq';
import { Injectable } from '@nestjs/common';
import type { Queue } from 'bullmq';
import {
  type AnalyticsJobData,
  type AnalyticsTrigger,
  JOBS,
  jobIds,
} from '../../queue/jobs.js';
import { QUEUES } from '../../queue/queue.constants.js';

@Injectable()
export class AnalyticsEnqueuer {
  constructor(
    @InjectQueue(QUEUES.ANALYTICS)
    private readonly queue: Queue<AnalyticsJobData>,
  ) {}

  async enqueue(
    scannedDomainId: string,
    trigger: AnalyticsTrigger,
    scanId?: string,
  ): Promise<string> {
    const scope =
      trigger === 'manual'
        ? `manual-${Date.now()}`
        : (scanId ?? `adhoc-${Date.now()}`);
    const job = await this.queue.add(
      JOBS.SCORE,
      { scannedDomainId, scanId, trigger },
      {
        jobId: jobIds.analytics(scannedDomainId, scope, trigger),
        attempts: 3,
        backoff: { type: 'exponential', delay: 5_000 },
      },
    );
    return job.id!;
  }
}
