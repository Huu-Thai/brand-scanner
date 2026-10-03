import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import type { Queue } from 'bullmq';
import { JOBS, jobIds, type OrchestrateJobData } from '../../../queue/jobs.js';
import { QUEUES } from '../../../queue/queue.constants.js';
import {
  ORIGINAL_DOMAIN_EVENTS,
  type OriginalDomainCreatedEvent,
  type OriginalDomainDeletedEvent,
  type OriginalDomainUpdatedEvent,
} from '../../original-domains/events/original-domain.events.js';
import { SCAN_EVENTS, type ScanCreatedEvent } from '../events/scan.events.js';
import { ScanScheduleService } from '../scan-schedule.service.js';
import { ScansService } from '../scans.service.js';

/** Turns domain events into queue work. Runs in whichever process emitted the event. */
@Injectable()
export class ScanLifecycleListener {
  private readonly logger = new Logger(ScanLifecycleListener.name);

  constructor(
    @InjectQueue(QUEUES.SCAN_ORCHESTRATOR)
    private readonly orchestrator: Queue<OrchestrateJobData>,
    private readonly scans: ScansService,
    private readonly schedules: ScanScheduleService,
  ) {}

  @OnEvent(SCAN_EVENTS.CREATED, { async: true, promisify: true })
  async onScanCreated(event: ScanCreatedEvent): Promise<void> {
    try {
      await this.orchestrator.add(
        JOBS.ORCHESTRATE,
        { scanId: event.scanId },
        { jobId: jobIds.orchestrate(event.scanId), attempts: 3 },
      );
    } catch (e) {
      // Never leave a QUEUED scan holding the "one active scan" slot without a job behind it.
      this.logger.error(
        `Could not enqueue scan ${event.scanId}: ${(e as Error).message}`,
      );
      await this.scans
        .fail(event.scanId, 'Could not enqueue scan job')
        .catch(() => undefined);
    }
  }

  // One decorator per event: with wildcard mode, an array is ONE namespaced event ("a.b"), not two.
  @OnEvent(ORIGINAL_DOMAIN_EVENTS.CREATED, { async: true, promisify: true })
  @OnEvent(ORIGINAL_DOMAIN_EVENTS.UPDATED, { async: true, promisify: true })
  async onOriginalDomainSaved(
    event: OriginalDomainCreatedEvent | OriginalDomainUpdatedEvent,
  ): Promise<void> {
    if (
      'changedFields' in event &&
      !event.changedFields.some((f) => f === 'scanSchedule' || f === 'isActive')
    ) {
      return;
    }
    await this.syncSchedule(() => this.schedules.sync(event.originalDomain));
  }

  @OnEvent(ORIGINAL_DOMAIN_EVENTS.DELETED, { async: true, promisify: true })
  async onOriginalDomainDeleted(
    event: OriginalDomainDeletedEvent,
  ): Promise<void> {
    await this.syncSchedule(() =>
      this.schedules.sync({ ...event.originalDomain, deleted: true }),
    );
    for (const id of await this.scans.activeScanIds(event.originalDomain.id)) {
      await this.scans
        .cancel(id)
        .catch((e: Error) =>
          this.logger.warn(`Could not cancel scan ${id}: ${e.message}`),
        );
    }
  }

  private async syncSchedule(fn: () => Promise<void>): Promise<void> {
    try {
      await fn();
    } catch (e) {
      // Reconciled again on next API start-up.
      this.logger.error(`Schedule sync failed: ${(e as Error).message}`);
    }
  }
}
