import { OnWorkerEvent, Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger, OnApplicationBootstrap } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Job } from 'bullmq';
import { JOBS, type BrandReferenceJobData } from '../../../queue/jobs.js';
import { BrandReferenceService } from '../brand-reference.service.js';
import { withJobContext } from '../../../common/utils/job-context.js';
import type { AppConfig } from '../../../config/configuration.js';
import type { ScreenshotJobData } from '../../../queue/jobs.js';
import { QUEUES } from '../../../queue/queue.constants.js';
import { ScannedDomainsQuery } from '../../scanned-domains/scanned-domains.query.js';
import { analyzeImage } from '../capture/image.js';
import {
  SeleniumCaptureService,
  SiteUnreachableError,
} from '../capture/selenium-capture.service.js';
import { ScreenshotsService } from '../screenshots.service.js';

/**
 * One capture per job. Concurrency comes from SCREENSHOT_CONCURRENCY and should match the
 * Grid's free session slots. An unreachable site is a definitive result (FAILED row, no retry);
 * Grid/session errors are retried and recorded as FAILED after the last attempt.
 */
@Processor(QUEUES.SCREENSHOT, { concurrency: 1 })
export class ScreenshotProcessor
  extends WorkerHost
  implements OnApplicationBootstrap
{
  private readonly logger = new Logger(ScreenshotProcessor.name);

  constructor(
    private readonly capture: SeleniumCaptureService,
    private readonly screenshots: ScreenshotsService,
    private readonly scannedDomains: ScannedDomainsQuery,
    private readonly config: ConfigService<AppConfig, true>,
    private readonly references: BrandReferenceService,
  ) {
    super();
  }

  onApplicationBootstrap(): void {
    this.worker.concurrency = this.config.get('enrichment', {
      infer: true,
    }).screenshotConcurrency;
  }

  process(job: Job<ScreenshotJobData>) {
    if (
      job.name === JOBS.CAPTURE_REFERENCE ||
      job.name === JOBS.REFRESH_REFERENCES
    )
      return this.reference(job as unknown as Job<BrandReferenceJobData>);
    return withJobContext(job, job.data.scanId, async () => {
      const sd = await this.scannedDomains.getForEnrichment(
        job.data.scannedDomainId,
      );
      if (!sd) return { skipped: 'scanned domain gone' };
      try {
        const capture = await this.capture.capture(sd.domain);
        const image = await analyzeImage(capture.png);
        const row = await this.screenshots.saveCaptured({
          scannedDomainId: sd.id,
          originalDomainId: sd.originalDomainId,
          scanId: job.data.scanId,
          capture,
          image,
        });
        return {
          screenshotId: row.id,
          finalUrl: capture.finalUrl,
          httpStatus: capture.httpStatus,
        };
      } catch (e) {
        if (e instanceof SiteUnreachableError) {
          const row = await this.screenshots.saveFailed(
            sd.id,
            sd.domain,
            e.message,
            job.data.scanId,
          );
          return { screenshotId: row.id, failed: e.message };
        }
        throw e;
      }
    });
  }

  private reference(job: Job<BrandReferenceJobData>) {
    return withJobContext(job, undefined, async () => {
      if (job.name === JOBS.REFRESH_REFERENCES)
        return { queued: await this.references.refreshAll() };
      const row = await this.references.captureNow(job.data.originalDomainId);
      return row ? { reference: row.status } : { skipped: 'brand gone' };
    });
  }

  @OnWorkerEvent('failed')
  async onFailed(job: Job<ScreenshotJobData>, error: Error): Promise<void> {
    if (job.attemptsMade < (job.opts.attempts ?? 1)) return;
    // Brand-reference jobs have no look-alike row to mark FAILED.
    if (
      job.name === JOBS.CAPTURE_REFERENCE ||
      job.name === JOBS.REFRESH_REFERENCES
    )
      return;
    this.logger.warn(
      `Screenshot gave up for ${job.data.domain}: ${error.message.split('\n')[0]}`,
    );
    await this.screenshots
      .saveFailed(
        job.data.scannedDomainId,
        job.data.domain,
        `capture failed: ${error.message.split('\n')[0]}`,
        job.data.scanId,
      )
      .catch(() => undefined);
  }
}
