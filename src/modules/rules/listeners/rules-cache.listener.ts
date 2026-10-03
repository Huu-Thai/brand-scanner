import { Injectable } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { RULE_CONFIG_EVENTS } from '../events/rule-config.events.js';
import { RuleEngineService } from '../rule-engine.service.js';

/** Scoring picks up rule/threshold edits immediately instead of waiting for the cache TTL. */
@Injectable()
export class RulesCacheListener {
  constructor(private readonly engine: RuleEngineService) {}

  // One decorator per event: with wildcard mode, an array is ONE namespaced event ("a.b"), not two.
  @OnEvent(RULE_CONFIG_EVENTS.UPDATED, { async: true, promisify: true })
  @OnEvent(RULE_CONFIG_EVENTS.THRESHOLDS_UPDATED, {
    async: true,
    promisify: true,
  })
  invalidate(): Promise<void> {
    return this.engine.invalidate();
  }
}
