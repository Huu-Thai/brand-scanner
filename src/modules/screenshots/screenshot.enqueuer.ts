import { InjectQueue } from '@nestjs/bullmq';
import { Injectable } from '@nestjs/common';
import type { Queue } from 'bullmq';
import { JOBS, jobIds, type ScreenshotJobData } from '../../queue/jobs.js';
import { QUEUES } from '../../queue/queue.constants.js';

@Injectable()
export class ScreenshotEnqueuer {
  constructor(
    @InjectQueue(QUEUES.SCREENSHOT)
    private readonly queue: Queue<ScreenshotJobData>,
  ) {}

  async enqueue(data: ScreenshotJobData, manual = false): Promise<string> {
    const scope = manual
      ? `manual-${Date.now()}`
      : (data.scanId ?? `adhoc-${Date.now()}`);
    const job = await this.queue.add(JOBS.CAPTURE, data, {
      jobId: jobIds.screenshot(data.scannedDomainId, scope),
      attempts: 2,
      backoff: { type: 'fixed', delay: 30_000 },
    });
    return job.id!;
  }
}
