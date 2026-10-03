import { Injectable } from '@nestjs/common';
import { TransactionalEventBus } from '../../common/events/transactional-event-bus.js';
import type { Prisma } from '../../database/generated/prisma/client.js';
import { ThreatLevel } from '../../database/generated/prisma/enums.js';
import type { AnalyticsModel } from '../../database/generated/prisma/models.js';
import type {
  DomainScoreResult,
  RuleEvaluationResult,
} from '../rules/rule.types.js';
import { RuleKey } from '../rules/rule.types.js';
import {
  AnalyticsBeforeCreateEvent,
  AnalyticsComputedEvent,
  HighRiskAlertEvent,
} from './events/analytics.events.js';

export interface RecordScoreInput {
  scannedDomainId: string;
  originalDomainId: string;
  domain: string;
  scanId?: string;
  previousThreatLevel: ThreatLevel;
  result: DomainScoreResult;
}

const value = (results: RuleEvaluationResult[], key: RuleKey) =>
  results.find((r) => r.key === key);
const asInt = (v: unknown) =>
  typeof v === 'number' && Number.isFinite(v) ? Math.round(v) : null;

/** Denormalised signal columns for filtering/reporting, extracted from the rule breakdown. */
export function extractSignals(results: RuleEvaluationResult[]) {
  const ssl = value(results, RuleKey.SSL_ISSUES);
  const dmarc = value(results, RuleKey.DMARC_MISSING);
  const mx = value(results, RuleKey.MX_RECORDS_FOUND);
  const spamhaus = value(results, RuleKey.SPAMHAUS_BLACKLIST);
  const reputation = value(results, RuleKey.REPUTATION_CHECK);
  return {
    levenshteinDistance: asInt(
      value(results, RuleKey.LEVENSHTEIN_DISTANCE)?.value,
    ),
    domainAgeDays: asInt(value(results, RuleKey.DOMAIN_AGE)?.value),
    sslStatus: typeof ssl?.value === 'string' ? ssl.value : null,
    dmarcPolicy: typeof dmarc?.value === 'string' ? dmarc.value : null,
    hasMx: mx ? mx.condition === 'exist' : null,
    spamhausListed:
      spamhaus && spamhaus.condition !== null
        ? spamhaus.condition === 'listed'
        : null,
    reputationHit:
      reputation &&
      typeof reputation.value === 'string' &&
      reputation.value.startsWith('unknown')
        ? null
        : reputation
          ? reputation.condition === 'found'
          : null,
  };
}

/** Appends a scoring result (analytics is an append-only time series). */
@Injectable()
export class AnalyticsService {
  constructor(private readonly bus: TransactionalEventBus) {}

  record(input: RecordScoreInput): Promise<AnalyticsModel> {
    const { result } = input;
    return this.bus.write({
      before: new AnalyticsBeforeCreateEvent(
        input.scannedDomainId,
        result.totalScore,
      ),
      work: async (tx, after) => {
        const row = await tx.analytics.create({
          data: {
            scannedDomainId: input.scannedDomainId,
            scanId: input.scanId,
            totalScore: result.totalScore,
            threatLevel: result.threatLevel,
            ruleResults: result.ruleResults as unknown as Prisma.InputJsonValue,
            ...extractSignals(result.ruleResults),
          },
        });
        after.add(
          new AnalyticsComputedEvent(
            row.id,
            input.scannedDomainId,
            input.scanId,
            result.totalScore,
            result.threatLevel,
            input.previousThreatLevel,
          ),
        );
        if (
          result.threatLevel === ThreatLevel.HIGH_RISK &&
          input.previousThreatLevel !== ThreatLevel.HIGH_RISK
        ) {
          after.add(
            new HighRiskAlertEvent(
              input.scannedDomainId,
              input.originalDomainId,
              input.domain,
              result.totalScore,
              result.ruleResults.filter((r) => r.matched).map((r) => r.key),
            ),
          );
        }
        return row;
      },
    });
  }
}
