import { EventEmitter2, EventEmitterModule } from '@nestjs/event-emitter';
import { Test } from '@nestjs/testing';
import { RulesCacheListener } from '../../modules/rules/listeners/rules-cache.listener.js';
import { RuleEngineService } from '../../modules/rules/rule-engine.service.js';
import { RULE_CONFIG_EVENTS } from '../../modules/rules/events/rule-config.events.js';
import { ScanLifecycleListener } from '../../modules/scans/listeners/scan-lifecycle.listener.js';
import { ScanScheduleService } from '../../modules/scans/scan-schedule.service.js';
import { ScansService } from '../../modules/scans/scans.service.js';
import { ORIGINAL_DOMAIN_EVENTS } from '../../modules/original-domains/events/original-domain.events.js';
import { getQueueToken } from '@nestjs/bullmq';
import { QUEUES } from '../../queue/queue.constants.js';

/**
 * Wires listeners through the REAL Nest event subsystem (same EventEmitter options as
 * EventsModule). Guards against registrations that look right but never fire — e.g.
 * `@OnEvent([a, b])`, which wildcard mode treats as the single namespaced event "a.b".
 */
describe('event listener wiring', () => {
  async function build() {
    const engine = { invalidate: vi.fn(async () => undefined) };
    const schedules = { sync: vi.fn(async () => undefined) };
    const moduleRef = await Test.createTestingModule({
      imports: [EventEmitterModule.forRoot({ wildcard: true, delimiter: '.' })],
      providers: [
        RulesCacheListener,
        ScanLifecycleListener,
        { provide: RuleEngineService, useValue: engine },
        { provide: ScanScheduleService, useValue: schedules },
        { provide: ScansService, useValue: {} },
        {
          provide: getQueueToken(QUEUES.SCAN_ORCHESTRATOR),
          useValue: { add: vi.fn() },
        },
      ],
    }).compile();
    await moduleRef.init();
    return {
      events: moduleRef.get(EventEmitter2),
      engine,
      schedules,
      moduleRef,
    };
  }

  it('rule and threshold updates both invalidate the scoring cache', async () => {
    const { events, engine, moduleRef } = await build();
    await events.emitAsync(RULE_CONFIG_EVENTS.UPDATED, {});
    await events.emitAsync(RULE_CONFIG_EVENTS.THRESHOLDS_UPDATED, {});
    expect(engine.invalidate).toHaveBeenCalledTimes(2);
    await moduleRef.close();
  });

  it('original-domain created and updated both sync the scan schedule', async () => {
    const { events, schedules, moduleRef } = await build();
    const originalDomain = {
      id: 'od',
      domain: 'x.com',
      isActive: true,
      scanSchedule: '0 2 * * *',
    };
    await events.emitAsync(ORIGINAL_DOMAIN_EVENTS.CREATED, { originalDomain });
    await events.emitAsync(ORIGINAL_DOMAIN_EVENTS.UPDATED, {
      originalDomain,
      changedFields: ['scanSchedule'],
    });
    expect(schedules.sync).toHaveBeenCalledTimes(2);
    await moduleRef.close();
  });
});
