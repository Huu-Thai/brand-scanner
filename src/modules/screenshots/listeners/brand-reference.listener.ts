import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import type { Queue } from 'bullmq';
import { JOBS, type BrandReferenceJobData } from '../../../queue/jobs.js';
import { QUEUES } from '../../../queue/queue.constants.js';
import {
  ORIGINAL_DOMAIN_EVENTS,
  type OriginalDomainCreatedEvent,
  type OriginalDomainUpdatedEvent,
} from '../../original-domains/events/original-domain.events.js';
import { BrandReferenceService } from '../brand-reference.service.js';

/** Capture the brand's own page when a brand is added (or its domain/activation changes). */
@Injectable()
export class BrandReferenceListener {
  private readonly logger = new Logger(BrandReferenceListener.name);

  constructor(private readonly references: BrandReferenceService) {}

  @OnEvent(ORIGINAL_DOMAIN_EVENTS.CREATED, { async: true, promisify: true })
  onCreated(e: OriginalDomainCreatedEvent): Promise<void> {
    return this.capture(e.originalDomain.id, e.originalDomain.isActive);
  }

  @OnEvent(ORIGINAL_DOMAIN_EVENTS.UPDATED, { async: true, promisify: true })
  async onUpdated(e: OriginalDomainUpdatedEvent): Promise<void> {
    if (e.changedFields.includes('isActive'))
      await this.capture(e.originalDomain.id, e.originalDomain.isActive);
  }

  private async capture(id: string, active: boolean): Promise<void> {
    if (!active) return;
    await this.references
      .enqueue(id)
      .catch((err: Error) =>
        this.logger.error(`Could not queue brand reference: ${err.message}`),
      );
  }
}

/** Weekly refresh of every brand's reference (job scheduler on the screenshot queue). */
@Injectable()
export class BrandReferenceScheduler {
  constructor(
    @InjectQueue(QUEUES.SCREENSHOT)
    private readonly queue: Queue<BrandReferenceJobData>,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.queue.upsertJobScheduler(
      'brand-references-weekly',
      { pattern: '0 5 * * 1', tz: 'UTC' },
      {
        name: JOBS.REFRESH_REFERENCES,
        data: { originalDomainId: '' },
        opts: { attempts: 1, removeOnComplete: { count: 20 } },
      },
    );
  }
}
