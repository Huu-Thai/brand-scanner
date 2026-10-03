import { InjectQueue } from '@nestjs/bullmq';
import { Injectable } from '@nestjs/common';
import type { Queue } from 'bullmq';
import { JOBS, jobIds, type ThreatFeedPushJobData } from '../../queue/jobs.js';
import { QUEUES } from '../../queue/queue.constants.js';

@Injectable()
export class ThreatFeedPushEnqueuer {
  constructor(
    @InjectQueue(QUEUES.THREAT_FEED_PUSH)
    private readonly queue: Queue<ThreatFeedPushJobData>,
  ) {}

  async enqueue(data: ThreatFeedPushJobData): Promise<string> {
    const job = await this.queue.add(JOBS.PUSH_INDICATOR, data, {
      jobId: jobIds.push(data.scannedDomainId, data.action),
      // threat-feed outages can last a while; keep trying for ~1h.
      attempts: 8,
      backoff: { type: 'exponential', delay: 15_000 },
      removeOnComplete: { age: 86_400, count: 5_000 },
      removeOnFail: { age: 7 * 86_400 },
    });
    return job.id!;
  }
}
