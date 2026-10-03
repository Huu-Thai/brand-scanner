import type { ConfigService } from '@nestjs/config';
import type { Redis } from 'ioredis';
import type { AppConfig } from '../../config/configuration.js';
import type { PrismaService } from '../../database/prisma.service.js';
import { BaseRule } from './base-rule.js';
import {
  RuleEngineService,
  RULES_CACHE_KEY,
  toRuleConfigRecord,
} from './rule-engine.service.js';
import { classify } from './rule.types.js';

class FixedRule extends BaseRule {
  constructor(
    readonly key: string,
    private readonly condition: string | Error,
  ) {
    super();
  }
  protected resolveCondition() {
    if (this.condition instanceof Error) throw this.condition;
    return { condition: this.condition, value: 1 };
  }
}

function setup(ttl = 60_000) {
  const store = new Map<string, string>();
  const redis = {
    get: vi.fn(async (k: string) => store.get(k) ?? null),
    set: vi.fn(async (k: string, v: string) => void store.set(k, v)),
    del: vi.fn(async (k: string) => void store.delete(k)),
  } as unknown as Redis;
  const prisma = {
    ruleConfig: {
      findMany: vi.fn(async () => [
        {
          key: 'a',
          name: 'A',
          enabled: true,
          points: [
            { condition: 'hit', points: 50 },
            { condition: 'default', points: 0 },
          ],
          params: {},
        },
        {
          key: 'b',
          name: 'B',
          enabled: true,
          points: [{ condition: 'hit', points: 40 }],
          params: {},
        },
        { key: 'boom', name: 'Boom', enabled: true, points: [], params: {} },
        { key: 'unknown', name: 'U', enabled: true, points: [], params: {} },
      ]),
    },
    scoringThreshold: {
      findUnique: vi.fn(async () => ({
        thresholdMediumRisk: 80,
        thresholdLowRisk: 40,
      })),
    },
  } as unknown as PrismaService & {
    ruleConfig: { findMany: ReturnType<typeof vi.fn> };
  };
  const config = {
    get: () => ({ rulesCacheTtlMs: ttl }),
  } as unknown as ConfigService<AppConfig, true>;
  const rules = [
    new FixedRule('a', 'hit'),
    new FixedRule('b', 'hit'),
    new FixedRule('boom', new Error('dns exploded')),
  ];
  // Constructor takes the 12 concrete rules; pad with the test doubles.
  const engine = new (
    RuleEngineService as unknown as new (...a: unknown[]) => RuleEngineService
  )(
    prisma,
    redis,
    config,
    ...rules,
    ...Array.from({ length: 9 }, (_, i) => new FixedRule(`pad${i}`, 'x')),
  );
  return { engine, prisma, redis, store };
}

const input = { originalDomain: 'paypal.com', fuzzerDomain: 'apypal.com' };

describe('RuleEngineService', () => {
  it('sums matched points, bands the total, and isolates a failing rule', async () => {
    const { engine } = setup();
    const result = await engine.score(input);
    expect(result.totalScore).toBe(90);
    expect(result.threatLevel).toBe('HIGH_RISK');
    expect(result.ruleResults.map((r) => r.key)).toEqual(['a', 'b', 'boom']); // unknown key skipped
    expect(result.ruleResults[2]).toMatchObject({
      points: 0,
      value: 'error: dns exploded',
    });
  });

  it('caches the rule context in Redis and reloads after invalidation', async () => {
    const { engine, prisma, store } = setup();
    await engine.score(input);
    await engine.score(input);
    expect(prisma.ruleConfig.findMany).toHaveBeenCalledOnce();
    expect(store.has(RULES_CACHE_KEY)).toBe(true);
    await engine.invalidate();
    await engine.score(input);
    expect(prisma.ruleConfig.findMany).toHaveBeenCalledTimes(2);
  });

  it('skips the cache entirely when RULES_CACHE_TTL_MS=0', async () => {
    const { engine, redis } = setup(0);
    await engine.score(input);
    expect(redis.get).not.toHaveBeenCalled();
  });
});

describe('classify / toRuleConfigRecord', () => {
  it('uses Reporting bands: < low → LOW, < medium → MEDIUM, else HIGH', () => {
    const t = { thresholdLowRisk: 40, thresholdMediumRisk: 80 };
    expect([0, 39, 40, 79, 80].map((s) => classify(s, t))).toEqual([
      'LOW_RISK',
      'LOW_RISK',
      'MEDIUM_RISK',
      'MEDIUM_RISK',
      'HIGH_RISK',
    ]);
  });

  it('drops malformed tiers and params', () => {
    expect(
      toRuleConfigRecord({
        key: 'k',
        name: 'n',
        enabled: true,
        points: [{ condition: 'a', points: 1 }, { nope: 1 }],
        params: [],
      } as never),
    ).toEqual({
      key: 'k',
      name: 'n',
      enabled: true,
      points: [{ condition: 'a', points: 1 }],
      params: {},
    });
  });
});
