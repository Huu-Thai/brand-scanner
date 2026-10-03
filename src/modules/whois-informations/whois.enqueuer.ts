import { InjectQueue } from '@nestjs/bullmq';
import { Injectable } from '@nestjs/common';
import type { Queue } from 'bullmq';
import { JOBS, jobIds, type WhoisJobData } from '../../queue/jobs.js';
import { QUEUES } from '../../queue/queue.constants.js';

@Injectable()
export class WhoisEnqueuer {
  constructor(
    @InjectQueue(QUEUES.WHOIS) private readonly queue: Queue<WhoisJobData>,
  ) {}

  async enqueue(data: WhoisJobData): Promise<string> {
    const scope = data.force
      ? `manual-${Date.now()}`
      : (data.scanId ?? 'adhoc');
    const job = await this.queue.add(JOBS.WHOIS_LOOKUP, data, {
      jobId: jobIds.whois(data.scannedDomainId, scope),
      attempts: 5,
      backoff: { type: 'exponential', delay: 30_000 },
    });
    return job.id!;
  }
}
