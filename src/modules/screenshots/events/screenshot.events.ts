import { BaseEvent } from '../../../common/events/base.event.js';

export const SCREENSHOT_EVENTS = {
  BEFORE_CREATE: 'screenshot.before-create',
  CAPTURED: 'screenshot.captured',
  FAILED: 'screenshot.failed',
  BEFORE_REFERENCE: 'brand-reference.before-capture',
  REFERENCE_CAPTURED: 'brand-reference.captured',
} as const;

export class ScreenshotBeforeCreateEvent extends BaseEvent {
  readonly name = SCREENSHOT_EVENTS.BEFORE_CREATE;
  constructor(
    readonly scannedDomainId: string,
    readonly status: string,
  ) {
    super();
  }
}

export class ScreenshotCapturedEvent extends BaseEvent {
  readonly name = SCREENSHOT_EVENTS.CAPTURED;
  constructor(
    readonly screenshotId: string,
    readonly scannedDomainId: string,
    readonly perceptualHash: string,
    readonly finalUrl: string,
  ) {
    super();
  }
}

export class ScreenshotFailedEvent extends BaseEvent {
  readonly name = SCREENSHOT_EVENTS.FAILED;
  constructor(
    readonly screenshotId: string,
    readonly scannedDomainId: string,
    readonly reason: string,
  ) {
    super();
  }
}

export class BrandReferenceBeforeCaptureEvent extends BaseEvent {
  readonly name = SCREENSHOT_EVENTS.BEFORE_REFERENCE;
  constructor(readonly originalDomainId: string) {
    super();
  }
}

/** The brand's own page was (re)captured — look-alikes with captures get rescored against it. */
export class BrandReferenceCapturedEvent extends BaseEvent {
  readonly name = SCREENSHOT_EVENTS.REFERENCE_CAPTURED;
  constructor(
    readonly originalDomainId: string,
    readonly status: 'CAPTURED' | 'FAILED',
    readonly perceptualHash: string | null,
  ) {
    super();
  }
}
