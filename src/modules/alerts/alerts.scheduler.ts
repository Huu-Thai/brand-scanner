import { InjectQueue } from '@nestjs/bullmq';
import {
  Injectable,
  Logger,
  type OnApplicationBootstrap,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Queue } from 'bullmq';
import type { AppConfig } from '../../config/configuration.js';
import { JOBS, type AlertJobData } from '../../queue/jobs.js';
import { QUEUES } from '../../queue/queue.constants.js';

export const DIGEST_SCHEDULER = 'alerts-digest';

@Injectable()
export class AlertsScheduler implements OnApplicationBootstrap {
  private readonly logger = new Logger(AlertsScheduler.name);

  constructor(
    @InjectQueue(QUEUES.ALERTS) private readonly queue: Queue<AlertJobData>,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    const cron = this.config.get('alerts', { infer: true }).digestCron;
    await this.queue.upsertJobScheduler(
      DIGEST_SCHEDULER,
      { pattern: cron, tz: 'UTC' },
      {
        name: JOBS.SEND_DIGEST,
        data: {},
        opts: {
          attempts: 1,
          removeOnComplete: { count: 100 },
          removeOnFail: { age: 31 * 86_400 },
        },
      },
    );
    this.logger.log(`Alert digests scheduled at "${cron}" (UTC)`);
  }
}
