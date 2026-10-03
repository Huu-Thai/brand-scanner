import { InjectQueue } from '@nestjs/bullmq';
import { Injectable } from '@nestjs/common';
import type { Queue } from 'bullmq';
import { JOBS, jobIds, type RescanJobData } from '../../queue/jobs.js';
import { QUEUES } from '../../queue/queue.constants.js';

@Injectable()
export class RescanEnqueuer {
  constructor(
    @InjectQueue(QUEUES.DOMAIN_RESCAN)
    private readonly queue: Queue<RescanJobData>,
  ) {}

  async enqueue(data: RescanJobData): Promise<string> {
    const job = await this.queue.add(JOBS.RESCAN, data, {
      jobId: jobIds.rescan(data.scannedDomainId),
      attempts: 3,
      backoff: { type: 'exponential', delay: 5_000 },
    });
    return job.id!;
  }
}
