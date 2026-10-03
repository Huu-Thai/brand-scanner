import { BrandReferenceController } from './brand-reference.controller.js';
import { BrandReferenceService } from './brand-reference.service.js';
import { BrandReferenceListener } from './listeners/brand-reference.listener.js';
import { Module } from '@nestjs/common';
import { ScannedDomainsModule } from '../scanned-domains/scanned-domains.module.js';
import { SeleniumCaptureService } from './capture/selenium-capture.service.js';
import { ScreenshotTriggerListener } from './listeners/screenshot-trigger.listener.js';
import { ScreenshotEnqueuer } from './screenshot.enqueuer.js';
import { ScreenshotsController } from './screenshots.controller.js';
import { ScreenshotsQuery } from './screenshots.query.js';
import { ScreenshotsService } from './screenshots.service.js';

@Module({
  imports: [ScannedDomainsModule],
  controllers: [ScreenshotsController, BrandReferenceController],
  providers: [
    BrandReferenceService,
    BrandReferenceListener,
    ScreenshotsService,
    ScreenshotsQuery,
    ScreenshotEnqueuer,
    ScreenshotTriggerListener,
    SeleniumCaptureService,
  ],
  exports: [
    ScreenshotsService,
    SeleniumCaptureService,
    ScreenshotsQuery,
    BrandReferenceService,
  ],
})
export class ScreenshotsModule {}
