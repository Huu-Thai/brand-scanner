import { InjectQueue } from '@nestjs/bullmq';
import {
  Injectable,
  Logger,
  type OnApplicationBootstrap,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Queue } from 'bullmq';
import type { AppConfig } from '../../config/configuration.js';
import { JOBS, type RetentionJobData } from '../../queue/jobs.js';
import { QUEUES } from '../../queue/queue.constants.js';

export const RETENTION_SCHEDULER = 'retention-daily';
export const SWEEP_SCHEDULER = 'retention-orphan-sweep';

const JOB_OPTS = {
  attempts: 3,
  backoff: { type: 'exponential' as const, delay: 60_000 },
  removeOnComplete: { age: 31 * 86_400, count: 100 },
  removeOnFail: { age: 31 * 86_400 },
};

/** Keeps the retention / orphan-sweep job schedulers in Redis in line with the config (UTC). */
@Injectable()
export class RetentionScheduler implements OnApplicationBootstrap {
  private readonly logger = new Logger(RetentionScheduler.name);

  constructor(
    @InjectQueue(QUEUES.RETENTION)
    private readonly queue: Queue<RetentionJobData>,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    const { cron, sweepCron } = this.config.get('retention', { infer: true });
    await this.queue.upsertJobScheduler(
      RETENTION_SCHEDULER,
      { pattern: cron, tz: 'UTC' },
      {
        name: JOBS.RETENTION_RUN,
        data: { requestedBy: 'schedule' },
        opts: JOB_OPTS,
      },
    );
    await this.queue.upsertJobScheduler(
      SWEEP_SCHEDULER,
      { pattern: sweepCron, tz: 'UTC' },
      {
        name: JOBS.ORPHAN_SWEEP,
        data: { requestedBy: 'schedule' },
        opts: JOB_OPTS,
      },
    );
    this.logger.log(
      `Retention scheduled at "${cron}", orphan sweep at "${sweepCron}" (UTC)`,
    );
  }
}

export async function enqueueManual(
  queue: Queue<RetentionJobData>,
  name: typeof JOBS.RETENTION_RUN | typeof JOBS.ORPHAN_SWEEP,
  requestedBy: string,
): Promise<string> {
  const job = await queue.add(
    name,
    { requestedBy },
    { ...JOB_OPTS, attempts: 1, jobId: `${name}-manual-${Date.now()}` },
  );
  return job.id!;
}
