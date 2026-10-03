import { BaseEvent } from '../../../common/events/base.event.js';
import type {
  DomainStatus,
  ReviewVerdict,
} from '../../../database/generated/prisma/enums.js';

export const REVIEW_EVENTS = {
  BEFORE_CREATE: 'review.before-create',
  CREATED: 'review.created',
} as const;

export class ReviewBeforeCreateEvent extends BaseEvent {
  readonly name = REVIEW_EVENTS.BEFORE_CREATE;
  constructor(
    readonly scannedDomainId: string,
    readonly verdict: ReviewVerdict,
    readonly reviewer: string,
  ) {
    super();
  }
}

/** Drives the look-alike's status (scanned-domains listener) and, via that, threat-feed sync. */
export class ReviewCreatedEvent extends BaseEvent {
  readonly name = REVIEW_EVENTS.CREATED;
  constructor(
    readonly reviewId: string,
    readonly scannedDomainId: string,
    readonly verdict: ReviewVerdict,
    readonly previousStatus: DomainStatus,
    readonly newStatus: DomainStatus,
    readonly reviewer: string,
  ) {
    super();
  }
}
