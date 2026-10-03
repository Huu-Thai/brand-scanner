import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { ScanScheduleService } from './scan-schedule.service.js';

/** API process only: makes BullMQ job schedulers match the database at start-up. */
@Injectable()
export class ScanScheduleReconciler implements OnApplicationBootstrap {
  private readonly logger = new Logger(ScanScheduleReconciler.name);

  constructor(private readonly schedules: ScanScheduleService) {}

  async onApplicationBootstrap(): Promise<void> {
    try {
      const { upserted, removed } = await this.schedules.reconcile();
      this.logger.log(
        `Scan schedules reconciled: ${upserted} active, ${removed} orphaned removed`,
      );
    } catch (e) {
      // Never block API start-up on Redis; schedules are re-synced on the next domain write or restart.
      this.logger.error(
        `Scan schedule reconciliation failed: ${(e as Error).message}`,
      );
    }
  }
}
