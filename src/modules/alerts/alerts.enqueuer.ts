import { InjectQueue } from '@nestjs/bullmq';
import { Injectable } from '@nestjs/common';
import type { Queue } from 'bullmq';
import { JOBS, type AlertJobData } from '../../queue/jobs.js';
import { QUEUES } from '../../queue/queue.constants.js';

export const ALERT_JOB_ATTEMPTS = 6;

@Injectable()
export class AlertsEnqueuer {
  constructor(
    @InjectQueue(QUEUES.ALERTS) private readonly queue: Queue<AlertJobData>,
  ) {}

  async enqueue(deliveryId: string): Promise<void> {
    await this.queue.add(
      JOBS.SEND_ALERT,
      { deliveryId },
      {
        jobId: `alert-${deliveryId}`, // one job per delivery, even if the event is redelivered
        attempts: ALERT_JOB_ATTEMPTS,
        backoff: { type: 'exponential', delay: 30_000 }, // 30 s … 16 min
        removeOnComplete: { age: 86_400, count: 10_000 },
        removeOnFail: { age: 7 * 86_400 },
      },
    );
  }
}
