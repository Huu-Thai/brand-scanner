import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import type { Queue } from 'bullmq';
import { TransactionalEventBus } from '../../common/events/transactional-event-bus.js';
import type { BrandReference } from '../../database/generated/prisma/client.js';
import { PrismaService } from '../../database/prisma.service.js';
import { JOBS, type BrandReferenceJobData } from '../../queue/jobs.js';
import { QUEUES } from '../../queue/queue.constants.js';
import { StorageService } from '../../storage/storage.service.js';
import { analyzeImage } from './capture/image.js';
import {
  SeleniumCaptureService,
  SiteUnreachableError,
} from './capture/selenium-capture.service.js';
import {
  BrandReferenceBeforeCaptureEvent,
  BrandReferenceCapturedEvent,
} from './events/screenshot.events.js';

/** Deterministic: a refresh overwrites the previous object, so references never orphan. */
export const referenceKey = (originalDomainId: string) =>
  `brand-references/${originalDomainId}.png`;

/**
 * Captures each brand's own landing page — the reference look-alike screenshots and favicons
 * are compared against (PLAN.md §14 #3). Captured on brand creation, weekly, or on demand.
 */
@Injectable()
export class BrandReferenceService {
  private readonly logger = new Logger(BrandReferenceService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: TransactionalEventBus,
    private readonly capture: SeleniumCaptureService,
    private readonly storage: StorageService,
    @InjectQueue(QUEUES.SCREENSHOT)
    private readonly queue: Queue<BrandReferenceJobData>,
  ) {}

  async enqueue(originalDomainId: string, manual = false): Promise<string> {
    const job = await this.queue.add(
      JOBS.CAPTURE_REFERENCE,
      { originalDomainId },
      {
        // One per brand per day unless asked for explicitly.
        jobId: `brand-ref-${originalDomainId}-${manual ? `manual-${Date.now()}` : new Date().toISOString().slice(0, 10)}`,
        attempts: 2,
        backoff: { type: 'fixed', delay: 60_000 },
        removeOnComplete: { count: 1_000 },
        removeOnFail: { age: 7 * 86_400 },
      },
    );
    return job.id!;
  }

  /** Weekly: refresh every active brand's reference. */
  async refreshAll(): Promise<number> {
    const brands = await this.prisma.originalDomain.findMany({
      where: { isActive: true, deletedAt: null },
      select: { id: true },
    });
    for (const b of brands) await this.enqueue(b.id);
    return brands.length;
  }

  async captureNow(originalDomainId: string): Promise<BrandReference | null> {
    const brand = await this.prisma.originalDomain.findFirst({
      where: { id: originalDomainId, deletedAt: null },
      select: { id: true, domain: true },
    });
    if (!brand) return null;
    let data: Omit<
      BrandReference,
      'id' | 'originalDomainId' | 'createdAt' | 'updatedAt'
    >;
    try {
      const shot = await this.capture.capture(brand.domain);
      const image = await analyzeImage(shot.png);
      const key = referenceKey(brand.id);
      await this.storage.putObject(key, shot.png, 'image/png');
      data = {
        status: 'CAPTURED',
        storageKey: key,
        perceptualHash: image.perceptualHash,
        faviconHash: shot.signals?.faviconHash ?? null,
        pageTitle: shot.pageTitle,
        finalUrl: shot.finalUrl,
        errorMessage: null,
        capturedAt: new Date(),
      };
    } catch (e) {
      if (!(e instanceof SiteUnreachableError)) throw e; // Grid trouble → job retry
      this.logger.warn(
        `Brand reference for ${brand.domain} unavailable: ${e.message}`,
      );
      // Keep the last good capture if there is one; only record the failure otherwise.
      const existing = await this.prisma.brandReference.findUnique({
        where: { originalDomainId },
      });
      if (existing?.status === 'CAPTURED') return existing;
      data = {
        status: 'FAILED',
        storageKey: null,
        perceptualHash: null,
        faviconHash: null,
        pageTitle: null,
        finalUrl: null,
        errorMessage: e.message.slice(0, 2_000),
        capturedAt: null,
      };
    }
    return this.bus.write({
      before: new BrandReferenceBeforeCaptureEvent(originalDomainId),
      work: async (tx, after) => {
        const row = await tx.brandReference.upsert({
          where: { originalDomainId },
          create: { originalDomainId, ...data },
          update: data,
        });
        after.add(
          new BrandReferenceCapturedEvent(
            originalDomainId,
            row.status as 'CAPTURED' | 'FAILED',
            row.perceptualHash,
          ),
        );
        return row;
      },
    });
  }

  async get(originalDomainId: string): Promise<BrandReference> {
    const row = await this.prisma.brandReference.findUnique({
      where: { originalDomainId },
    });
    if (!row)
      throw new NotFoundException(
        `No reference capture for original domain ${originalDomainId} yet`,
      );
    return row;
  }

  async imageUrl(originalDomainId: string): Promise<string> {
    const row = await this.get(originalDomainId);
    if (!row.storageKey)
      throw new NotFoundException('The brand site could not be captured');
    return this.storage.getSignedUrl(row.storageKey);
  }
}
