import { BaseEvent } from '../../../common/events/base.event.js';

export const RULE_CONFIG_EVENTS = {
  BEFORE_UPDATE: 'rule-config.before-update',
  UPDATED: 'rule-config.updated',
  BEFORE_THRESHOLDS_UPDATE: 'scoring-thresholds.before-update',
  THRESHOLDS_UPDATED: 'scoring-thresholds.updated',
} as const;

export class RuleConfigBeforeUpdateEvent extends BaseEvent {
  readonly name = RULE_CONFIG_EVENTS.BEFORE_UPDATE;
  constructor(
    readonly key: string,
    readonly changes: Record<string, unknown>,
  ) {
    super();
  }
}

export class RuleConfigUpdatedEvent extends BaseEvent {
  readonly name = RULE_CONFIG_EVENTS.UPDATED;
  constructor(
    readonly key: string,
    readonly actor: string,
  ) {
    super();
  }
}

export class ScoringThresholdsBeforeUpdateEvent extends BaseEvent {
  readonly name = RULE_CONFIG_EVENTS.BEFORE_THRESHOLDS_UPDATE;
  constructor(readonly changes: Record<string, unknown>) {
    super();
  }
}

export class ScoringThresholdsUpdatedEvent extends BaseEvent {
  readonly name = RULE_CONFIG_EVENTS.THRESHOLDS_UPDATED;
  constructor(readonly actor: string) {
    super();
  }
}
