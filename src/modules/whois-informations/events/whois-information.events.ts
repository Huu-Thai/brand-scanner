import { BaseEvent } from '../../../common/events/base.event.js';

export const WHOIS_EVENTS = {
  BEFORE_CREATE: 'whois-information.before-create',
  CREATED: 'whois-information.created',
  FAILED: 'whois-information.failed',
} as const;

export class WhoisInformationBeforeCreateEvent extends BaseEvent {
  readonly name = WHOIS_EVENTS.BEFORE_CREATE;
  constructor(
    readonly scannedDomainId: string,
    readonly source: string,
  ) {
    super();
  }
}

export class WhoisInformationCreatedEvent extends BaseEvent {
  readonly name = WHOIS_EVENTS.CREATED;
  constructor(
    readonly whoisInformationId: string,
    readonly scannedDomainId: string,
    readonly scanId: string | undefined,
    readonly parseSucceeded: boolean,
  ) {
    super();
  }
}

/** Lookup gave up after all retries (no row written) — scoring proceeds without WHOIS signals. */
export class WhoisInformationFailedEvent extends BaseEvent {
  readonly name = WHOIS_EVENTS.FAILED;
  constructor(
    readonly scannedDomainId: string,
    readonly scanId: string | undefined,
    readonly reason: string,
  ) {
    super();
  }
}
