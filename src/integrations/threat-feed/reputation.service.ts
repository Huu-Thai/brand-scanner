import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Redis } from 'ioredis';
import type { AppConfig } from '../../config/configuration.js';
import { REDIS_CLIENT } from '../../redis/redis.module.js';
import { CircuitBreaker, CircuitOpenError } from './circuit-breaker.js';
import { type IndicatorType, ThreatFeedClient } from './threat-feed.client.js';

export type ReputationVerdict =
  | {
      status: 'found';
      indicatorType: IndicatorType;
      value: string;
      severity: string | null;
    }
  | { status: 'not_found' }
  | { status: 'unknown'; reason: string };

const CACHE_PREFIX = 'cache:reputation:';

/**
 * Is a look-alike (or the IP it resolves to) an active indicator in manage-feed?
 * Results are cached in Redis; a threat-feed outage yields `unknown` (rule scores 0)
 * instead of failing the analytics job.
 */
@Injectable()
export class ReputationService {
  private readonly logger = new Logger(ReputationService.name);
  private readonly breaker = new CircuitBreaker(5, 60_000);

  constructor(
    private readonly client: ThreatFeedClient,
    @Inject(REDIS_CLIENT) private readonly redis: Redis,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  async check(domain: string, ipv4?: string): Promise<ReputationVerdict> {
    if (!this.client.enabled)
      return { status: 'unknown', reason: 'threat-feed integration disabled' };
    const candidates: [IndicatorType, string][] = [
      ['DOMAIN', domain.toLowerCase()],
    ];
    if (ipv4) candidates.push(['IPV4', ipv4]);

    for (const [type, value] of candidates) {
      const verdict = await this.lookup(type, value);
      if (verdict.status !== 'not_found') return verdict; // found, or unknown (can't conclude)
    }
    return { status: 'not_found' };
  }

  /** Drops a cached verdict so the next score reflects an indicator we just published/retired. */
  async invalidate(type: IndicatorType, value: string): Promise<void> {
    await this.redis
      .del(`${CACHE_PREFIX}${type}:${value.toLowerCase()}`)
      .catch(() => undefined);
  }

  private async lookup(
    type: IndicatorType,
    value: string,
  ): Promise<ReputationVerdict> {
    const key = `${CACHE_PREFIX}${type}:${value}`;
    const cached = await this.redis.get(key).catch(() => null);
    if (cached) return JSON.parse(cached) as ReputationVerdict;

    let verdict: ReputationVerdict;
    try {
      const hit = await this.breaker.exec(() =>
        this.client.findActiveIndicator(type, value),
      );
      verdict = hit
        ? {
            status: 'found',
            indicatorType: type,
            value: hit.value,
            severity: hit.severity,
          }
        : { status: 'not_found' };
    } catch (e) {
      const reason =
        e instanceof CircuitOpenError
          ? 'threat-feed circuit open'
          : (e as Error).message;
      if (!(e instanceof CircuitOpenError))
        this.logger.warn(
          `Reputation lookup failed for ${type} ${value}: ${reason}`,
        );
      return { status: 'unknown', reason };
    }

    const { cacheTtlSeconds, missTtlSeconds } = this.config.get('threatFeed', {
      infer: true,
    });
    const ttl = verdict.status === 'found' ? cacheTtlSeconds : missTtlSeconds;
    if (ttl > 0)
      await this.redis
        .set(key, JSON.stringify(verdict), 'EX', ttl)
        .catch(() => undefined);
    return verdict;
  }
}
