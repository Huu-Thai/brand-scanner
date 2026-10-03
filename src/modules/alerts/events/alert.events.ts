import { BaseEvent } from '../../../common/events/base.event.js';
import type { AlertEventType } from '../../../database/generated/prisma/enums.js';

export const ALERT_EVENTS = {
  BEFORE_CHANNEL_WRITE: 'alert-channel.before-write',
  CHANNEL_WRITTEN: 'alert-channel.written',
  BEFORE_SUBSCRIPTION_WRITE: 'alert-subscription.before-write',
  SUBSCRIPTION_WRITTEN: 'alert-subscription.written',
  BEFORE_RAISE: 'alert.before-raise',
  QUEUED: 'alert.queued',
} as const;

export type WriteAction = 'create' | 'update' | 'delete';

export class AlertChannelBeforeWriteEvent extends BaseEvent {
  readonly name = ALERT_EVENTS.BEFORE_CHANNEL_WRITE;
  constructor(
    readonly action: WriteAction,
    readonly channelId: string | null,
    readonly actor: string,
  ) {
    super();
  }
}

export class AlertChannelWrittenEvent extends BaseEvent {
  readonly name = ALERT_EVENTS.CHANNEL_WRITTEN;
  constructor(
    readonly action: WriteAction,
    readonly channelId: string,
    readonly actor: string,
  ) {
    super();
  }
}

export class AlertSubscriptionBeforeWriteEvent extends BaseEvent {
  readonly name = ALERT_EVENTS.BEFORE_SUBSCRIPTION_WRITE;
  constructor(
    readonly action: WriteAction,
    readonly subscriptionId: string | null,
    readonly actor: string,
  ) {
    super();
  }
}

export class AlertSubscriptionWrittenEvent extends BaseEvent {
  readonly name = ALERT_EVENTS.SUBSCRIPTION_WRITTEN;
  constructor(
    readonly action: WriteAction,
    readonly subscriptionId: string,
    readonly actor: string,
  ) {
    super();
  }
}

export class AlertBeforeRaiseEvent extends BaseEvent {
  readonly name = ALERT_EVENTS.BEFORE_RAISE;
  constructor(
    readonly eventType: AlertEventType,
    readonly scannedDomainId: string,
    readonly subscriptions: number,
  ) {
    super();
  }
}

/** An IMMEDIATE delivery row was committed → enqueue it (via the outbox, so never lost). */
export class AlertQueuedEvent extends BaseEvent {
  readonly name = ALERT_EVENTS.QUEUED;
  constructor(
    readonly deliveryId: string,
    readonly channelId: string,
    readonly eventType: AlertEventType,
  ) {
    super();
  }
}
