import { BadRequestException, NotFoundException } from '@nestjs/common';
import type { PrismaService } from '../../database/prisma.service.js';
import { fakeBus } from '../../testing/fake-bus.js';
import { RULE_CONFIG_EVENTS } from './events/rule-config.events.js';
import { RulesCacheListener } from './listeners/rules-cache.listener.js';
import type { RuleEngineService } from './rule-engine.service.js';
import { RuleConfigsService } from './rule-configs.service.js';

function setup(exists = true) {
  const row = {
    key: 'domain_age',
    name: 'Domain Age',
    enabled: true,
    points: [{ condition: 'default', points: 0 }],
    params: {},
  };
  const tx = {
    ruleConfig: {
      findUnique: vi.fn(async () => (exists ? row : null)),
      update: vi.fn(async ({ data }) => ({ ...row, ...data })),
    },
    scoringThreshold: { update: vi.fn(async ({ data }) => data) },
  };
  const bus = fakeBus(tx);
  return {
    service: new RuleConfigsService({} as PrismaService, bus.bus),
    tx,
    ...bus,
  };
}

describe('RuleConfigsService', () => {
  it('updates a rule and emits rule-config.updated with the actor', async () => {
    const t = setup();
    const dto = await t.service.update(
      'domain_age',
      { enabled: false, points: [{ condition: 'default', points: 0 }] },
      'ops',
    );
    expect(dto.enabled).toBe(false);
    expect(t.after[0]).toMatchObject({
      name: RULE_CONFIG_EVENTS.UPDATED,
      key: 'domain_age',
      actor: 'ops',
    });
  });

  it('requires a default tier and an existing rule', async () => {
    await expect(
      setup().service.update(
        'domain_age',
        { points: [{ condition: '30', points: 5 }] },
        'ops',
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      setup(false).service.update('nope', { enabled: true }, 'ops'),
    ).rejects.toBeInstanceOf(NotFoundException);
  });

  it('validates threshold ordering', async () => {
    const t = setup();
    await expect(
      t.service.updateThresholds(
        { thresholdLowRisk: 80, thresholdMediumRisk: 40 },
        'ops',
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(
      await t.service.updateThresholds(
        { thresholdLowRisk: 30, thresholdMediumRisk: 70 },
        'ops',
      ),
    ).toEqual({
      thresholdLowRisk: 30,
      thresholdMediumRisk: 70,
    });
    expect(t.afterNames()).toEqual([RULE_CONFIG_EVENTS.THRESHOLDS_UPDATED]);
  });

  it('invalidates the scoring cache on change', async () => {
    const engine = {
      invalidate: vi.fn(async () => undefined),
    } as unknown as RuleEngineService;
    await new RulesCacheListener(engine).invalidate();
    expect(engine.invalidate).toHaveBeenCalled();
  });
});
