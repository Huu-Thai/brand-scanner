import { BaseEvent } from '../../../common/events/base.event.js';
import type { ThreatLevel } from '../../../database/generated/prisma/enums.js';

export const ANALYTICS_EVENTS = {
  BEFORE_CREATE: 'analytics.before-create',
  COMPUTED: 'analytics.computed',
  ALERT_HIGH_RISK: 'alert.high-risk',
} as const;

export class AnalyticsBeforeCreateEvent extends BaseEvent {
  readonly name = ANALYTICS_EVENTS.BEFORE_CREATE;
  constructor(
    readonly scannedDomainId: string,
    readonly totalScore: number,
  ) {
    super();
  }
}

export class AnalyticsComputedEvent extends BaseEvent {
  readonly name = ANALYTICS_EVENTS.COMPUTED;
  constructor(
    readonly analyticsId: string,
    readonly scannedDomainId: string,
    readonly scanId: string | undefined,
    readonly totalScore: number,
    readonly threatLevel: ThreatLevel,
    readonly previousThreatLevel: ThreatLevel,
  ) {
    super();
  }
}

/** A look-alike just became HIGH_RISK (hook for notifications in Phase 5). */
export class HighRiskAlertEvent extends BaseEvent {
  readonly name = ANALYTICS_EVENTS.ALERT_HIGH_RISK;
  constructor(
    readonly scannedDomainId: string,
    readonly originalDomainId: string,
    readonly domain: string,
    readonly totalScore: number,
    readonly matchedRules: string[],
  ) {
    super();
  }
}
