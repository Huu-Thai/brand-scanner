import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger } from '@nestjs/common';
import type { Queue } from 'bullmq';
import { JOBS, jobIds, type ScheduledScanJobData } from '../../queue/jobs.js';
import { QUEUES } from '../../queue/queue.constants.js';
import { OriginalDomainsQuery } from '../original-domains/original-domains.query.js';

export interface SchedulableDomain {
  id: string;
  isActive: boolean;
  scanSchedule: string | null;
  deleted?: boolean;
}

/** Mirrors each original domain's cron into a BullMQ job scheduler (UTC). */
@Injectable()
export class ScanScheduleService {
  private readonly logger = new Logger(ScanScheduleService.name);

  constructor(
    @InjectQueue(QUEUES.SCHEDULER)
    private readonly queue: Queue<ScheduledScanJobData>,
    private readonly originalDomains: OriginalDomainsQuery,
  ) {}

  async sync(domain: SchedulableDomain): Promise<void> {
    const key = jobIds.schedule(domain.id);
    if (!domain.deleted && domain.isActive && domain.scanSchedule) {
      await this.queue.upsertJobScheduler(
        key,
        { pattern: domain.scanSchedule, tz: 'UTC' },
        {
          name: JOBS.SCHEDULED_SCAN,
          data: { originalDomainId: domain.id },
          opts: { attempts: 1 },
        },
      );
      this.logger.log(
        `Scheduled scans for ${domain.id} at "${domain.scanSchedule}" (UTC)`,
      );
    } else if (await this.queue.removeJobScheduler(key)) {
      this.logger.log(`Removed scan schedule for ${domain.id}`);
    }
  }

  /** Makes Redis match the database (run at API start-up): adds missing, removes orphaned schedulers. */
  async reconcile(): Promise<{ upserted: number; removed: number }> {
    const scheduled = await this.originalDomains.findScheduled();
    for (const d of scheduled)
      await this.sync({
        id: d.id,
        isActive: true,
        scanSchedule: d.scanSchedule,
      });

    const wanted = new Set(scheduled.map((d) => jobIds.schedule(d.id)));
    let removed = 0;
    for (const scheduler of await this.queue.getJobSchedulers()) {
      if (scheduler.key && !wanted.has(scheduler.key)) {
        await this.queue.removeJobScheduler(scheduler.key);
        removed++;
      }
    }
    return { upserted: scheduled.length, removed };
  }
}
