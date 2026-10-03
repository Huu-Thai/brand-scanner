import { BaseEvent } from '../../../common/events/base.event.js';

export const ORIGINAL_DOMAIN_EVENTS = {
  BEFORE_CREATE: 'original-domain.before-create',
  CREATED: 'original-domain.created',
  BEFORE_UPDATE: 'original-domain.before-update',
  UPDATED: 'original-domain.updated',
  BEFORE_DELETE: 'original-domain.before-delete',
  DELETED: 'original-domain.deleted',
} as const;

export interface OriginalDomainSnapshot {
  id: string;
  domain: string;
  isActive: boolean;
  scanSchedule: string | null;
}

export class OriginalDomainBeforeCreateEvent extends BaseEvent {
  readonly name = ORIGINAL_DOMAIN_EVENTS.BEFORE_CREATE;
  constructor(readonly domain: string) {
    super();
  }
}

export class OriginalDomainCreatedEvent extends BaseEvent {
  readonly name = ORIGINAL_DOMAIN_EVENTS.CREATED;
  constructor(
    readonly originalDomain: OriginalDomainSnapshot,
    readonly restored = false,
  ) {
    super();
  }
}

export class OriginalDomainBeforeUpdateEvent extends BaseEvent {
  readonly name = ORIGINAL_DOMAIN_EVENTS.BEFORE_UPDATE;
  constructor(
    readonly id: string,
    readonly changes: Record<string, unknown>,
  ) {
    super();
  }
}

export class OriginalDomainUpdatedEvent extends BaseEvent {
  readonly name = ORIGINAL_DOMAIN_EVENTS.UPDATED;
  constructor(
    readonly originalDomain: OriginalDomainSnapshot,
    readonly changedFields: string[],
  ) {
    super();
  }
}

export class OriginalDomainBeforeDeleteEvent extends BaseEvent {
  readonly name = ORIGINAL_DOMAIN_EVENTS.BEFORE_DELETE;
  constructor(readonly id: string) {
    super();
  }
}

export class OriginalDomainDeletedEvent extends BaseEvent {
  readonly name = ORIGINAL_DOMAIN_EVENTS.DELETED;
  constructor(readonly originalDomain: OriginalDomainSnapshot) {
    super();
  }
}
