import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Redis } from 'ioredis';
import type { AppConfig } from '../../config/configuration.js';
import type { RuleConfigModel } from '../../database/generated/prisma/models.js';
import { PrismaService } from '../../database/prisma.service.js';
import { REDIS_CLIENT } from '../../redis/redis.module.js';
import type { BaseRule } from './base-rule.js';
import {
  DnsResolvesRule,
  DomainAgeRule,
  LevenshteinDistanceRule,
  LowTtlRule,
  MxRecordsFoundRule,
  SuspiciousTldRule,
} from './rules/local.rules.js';
import {
  DmarcMissingRule,
  ReputationCheckRule,
  SpamhausBlacklistRule,
  SslIssuesRule,
} from './rules/network.rules.js';
import {
  PhishingContentRule,
  VisualSimilarityRule,
} from './rules/content.rules.js';
import {
  classify,
  type DomainScoreResult,
  type RuleConfigRecord,
  type RuleEvaluationInput,
  type RuleEvaluationResult,
  type RulePointTier,
  type RuleScoringContext,
} from './rule.types.js';

export const RULES_CACHE_KEY = 'cache:rules:context';
const THRESHOLD_KEY = 'global_score';
const DEFAULT_THRESHOLDS = { thresholdMediumRisk: 80, thresholdLowRisk: 40 };

/** Narrows Prisma JSON columns to the shapes rules consume; malformed JSON degrades to empty. */
export function toRuleConfigRecord(row: RuleConfigModel): RuleConfigRecord {
  const points = Array.isArray(row.points)
    ? (row.points as unknown[]).filter(
        (t): t is RulePointTier =>
          !!t &&
          typeof (t as RulePointTier).condition === 'string' &&
          typeof (t as RulePointTier).points === 'number',
      )
    : [];
  const params =
    row.params && typeof row.params === 'object' && !Array.isArray(row.params)
      ? (row.params as Record<string, unknown>)
      : {};
  return { key: row.key, name: row.name, enabled: row.enabled, points, params };
}

/**
 * Scores one look-alike: every configured rule runs in parallel, points are summed and the
 * total is banded with `scoring_thresholds`. Rule tiers/thresholds live in the DB (editable
 * via the API) and are cached in Redis for RULES_CACHE_TTL_MS.
 */
@Injectable()
export class RuleEngineService {
  private readonly logger = new Logger(RuleEngineService.name);
  private readonly rules: Map<string, BaseRule>;

  constructor(
    private readonly prisma: PrismaService,
    @Inject(REDIS_CLIENT) private readonly redis: Redis,
    private readonly config: ConfigService<AppConfig, true>,
    levenshtein: LevenshteinDistanceRule,
    suspiciousTld: SuspiciousTldRule,
    ssl: SslIssuesRule,
    dmarc: DmarcMissingRule,
    domainAge: DomainAgeRule,
    reputation: ReputationCheckRule,
    mx: MxRecordsFoundRule,
    dnsResolves: DnsResolvesRule,
    lowTtl: LowTtlRule,
    spamhaus: SpamhausBlacklistRule,
    visual: VisualSimilarityRule,
    content: PhishingContentRule,
  ) {
    const all: BaseRule[] = [
      levenshtein,
      suspiciousTld,
      ssl,
      dmarc,
      domainAge,
      reputation,
      mx,
      dnsResolves,
      lowTtl,
      spamhaus,
      visual,
      content,
    ];
    this.rules = new Map(all.map((r) => [r.key, r]));
  }

  async loadContext(): Promise<RuleScoringContext> {
    const ttl = this.config.get('enrichment', { infer: true }).rulesCacheTtlMs;
    if (ttl > 0) {
      const cached = await this.redis.get(RULES_CACHE_KEY).catch(() => null);
      if (cached) return JSON.parse(cached) as RuleScoringContext;
    }
    const [rows, thresholds] = await Promise.all([
      this.prisma.ruleConfig.findMany({ orderBy: { key: 'asc' } }),
      this.prisma.scoringThreshold.findUnique({
        where: { key: THRESHOLD_KEY },
      }),
    ]);
    const context: RuleScoringContext = {
      configs: rows.map(toRuleConfigRecord),
      thresholds: thresholds
        ? {
            thresholdMediumRisk: thresholds.thresholdMediumRisk,
            thresholdLowRisk: thresholds.thresholdLowRisk,
          }
        : DEFAULT_THRESHOLDS,
    };
    if (ttl > 0)
      await this.redis
        .set(RULES_CACHE_KEY, JSON.stringify(context), 'PX', ttl)
        .catch(() => undefined);
    return context;
  }

  async invalidate(): Promise<void> {
    await this.redis.del(RULES_CACHE_KEY).catch(() => undefined);
  }

  async score(
    input: RuleEvaluationInput,
    context?: RuleScoringContext,
  ): Promise<DomainScoreResult> {
    const { configs, thresholds } = context ?? (await this.loadContext());
    const evaluations = await Promise.all(
      configs.map(async (config): Promise<RuleEvaluationResult | null> => {
        const rule = this.rules.get(config.key);
        if (!rule) {
          this.logger.warn(
            `No handler for rule_configs.key "${config.key}" — skipped`,
          );
          return null;
        }
        try {
          return await rule.evaluate(config, input);
        } catch (e) {
          // One misbehaving rule must not sink the whole score.
          this.logger.warn(
            `Rule ${config.key} failed for ${input.fuzzerDomain}: ${(e as Error).message}`,
          );
          return {
            key: config.key,
            matched: false,
            condition: null,
            value: `error: ${(e as Error).message}`,
            points: 0,
          };
        }
      }),
    );
    const ruleResults = evaluations.filter(
      (r): r is RuleEvaluationResult => r !== null,
    );
    const totalScore = ruleResults.reduce((sum, r) => sum + r.points, 0);
    return {
      totalScore,
      threatLevel: classify(totalScore, thresholds),
      thresholds,
      ruleResults,
    };
  }
}
