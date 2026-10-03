import { randomUUID } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { TransactionalEventBus } from '../../common/events/transactional-event-bus.js';
import { ScreenshotStatus } from '../../database/generated/prisma/enums.js';
import type { ScreenshotModel } from '../../database/generated/prisma/models.js';
import { StorageService } from '../../storage/storage.service.js';
import type { CaptureResult } from './capture/selenium-capture.service.js';
import type { ImageInfo } from './capture/image.js';
import {
  ScreenshotBeforeCreateEvent,
  ScreenshotCapturedEvent,
  ScreenshotFailedEvent,
} from './events/screenshot.events.js';

export interface CapturedInput {
  scannedDomainId: string;
  originalDomainId: string;
  scanId?: string;
  capture: CaptureResult;
  image: ImageInfo;
}

export const screenshotKey = (
  originalDomainId: string,
  scannedDomainId: string,
  id: string,
) => `screenshots/${originalDomainId}/${scannedDomainId}/${id}.png`;

/** Persists captures: object first, then the row (with a compensating delete if the row fails). */
@Injectable()
export class ScreenshotsService {
  private readonly logger = new Logger(ScreenshotsService.name);

  constructor(
    private readonly bus: TransactionalEventBus,
    private readonly storage: StorageService,
  ) {}

  async saveCaptured(input: CapturedInput): Promise<ScreenshotModel> {
    const id = randomUUID();
    const key = screenshotKey(
      input.originalDomainId,
      input.scannedDomainId,
      id,
    );
    await this.storage.putObject(key, input.capture.png, 'image/png');
    try {
      return await this.bus.write({
        before: new ScreenshotBeforeCreateEvent(
          input.scannedDomainId,
          ScreenshotStatus.CAPTURED,
        ),
        work: async (tx, after) => {
          const row = await tx.screenshot.create({
            data: {
              id,
              scannedDomainId: input.scannedDomainId,
              scanId: input.scanId,
              status: ScreenshotStatus.CAPTURED,
              storageBucket: this.storage.bucket,
              storageKey: key,
              mimeType: 'image/png',
              sizeBytes: input.image.sizeBytes,
              width: input.image.width,
              height: input.image.height,
              requestedUrl: input.capture.requestedUrl,
              finalUrl: input.capture.finalUrl.slice(0, 2_000),
              httpStatus: input.capture.httpStatus,
              pageTitle: input.capture.pageTitle,
              perceptualHash: input.image.perceptualHash,
              faviconHash: input.capture.signals?.faviconHash ?? null,
              pageSignals: input.capture.signals
                ? {
                    hasPasswordField: input.capture.signals.hasPasswordField,
                    formActionHosts: input.capture.signals.formActionHosts,
                    text: input.capture.signals.text,
                  }
                : undefined,
              capturedAt: new Date(),
            },
          });
          after.add(
            new ScreenshotCapturedEvent(
              id,
              input.scannedDomainId,
              input.image.perceptualHash,
              input.capture.finalUrl,
            ),
          );
          return row;
        },
      });
    } catch (e) {
      await this.storage
        .deleteObjects([key])
        .catch((err: Error) =>
          this.logger.error(
            `Orphaned object ${key} (compensating delete failed: ${err.message})`,
          ),
        );
      throw e;
    }
  }

  saveFailed(
    scannedDomainId: string,
    domain: string,
    reason: string,
    scanId?: string,
  ): Promise<ScreenshotModel> {
    return this.bus.write({
      before: new ScreenshotBeforeCreateEvent(
        scannedDomainId,
        ScreenshotStatus.FAILED,
      ),
      work: async (tx, after) => {
        const row = await tx.screenshot.create({
          data: {
            scannedDomainId,
            scanId,
            status: ScreenshotStatus.FAILED,
            requestedUrl: `https://${domain}/`,
            errorMessage: reason.slice(0, 1_000),
          },
        });
        after.add(new ScreenshotFailedEvent(row.id, scannedDomainId, reason));
        return row;
      },
    });
  }
}
