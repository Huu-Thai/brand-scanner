import { Injectable } from '@nestjs/common';
import type { AnalyticsModel } from '../../database/generated/prisma/models.js';
import { PrismaService } from '../../database/prisma.service.js';
import { ScannedDomainsQuery } from '../scanned-domains/scanned-domains.query.js';
import type {
  AnalyticsDto,
  RuleResultDto,
  SummaryDto,
  TrendPointDto,
} from './dto/analytics.dto.js';

export function toAnalyticsDto(row: AnalyticsModel): AnalyticsDto {
  return {
    id: row.id,
    scannedDomainId: row.scannedDomainId,
    scanId: row.scanId,
    totalScore: row.totalScore,
    threatLevel: row.threatLevel,
    ruleResults: (row.ruleResults ?? []) as unknown as RuleResultDto[],
    levenshteinDistance: row.levenshteinDistance,
    domainAgeDays: row.domainAgeDays,
    sslStatus: row.sslStatus,
    dmarcPolicy: row.dmarcPolicy,
    hasMx: row.hasMx,
    spamhausListed: row.spamhausListed,
    reputationHit: row.reputationHit,
    computedAt: row.computedAt,
  };
}

const day = (d: Date) => d.toISOString().slice(0, 10);

@Injectable()
export class AnalyticsQuery {
  constructor(
    private readonly prisma: PrismaService,
    private readonly scannedDomains: ScannedDomainsQuery,
  ) {}

  async history(scannedDomainId: string, limit = 20): Promise<AnalyticsDto[]> {
    const rows = await this.prisma.analytics.findMany({
      where: { scannedDomainId },
      orderBy: { computedAt: 'desc' },
      take: limit,
    });
    return rows.map(toAnalyticsDto);
  }

  summary(originalDomainId?: string): Promise<SummaryDto> {
    return this.scannedDomains.summary(originalDomainId);
  }

  async trends(
    days: number,
    originalDomainId?: string,
  ): Promise<TrendPointDto[]> {
    const since = new Date(
      Date.UTC(
        new Date().getUTCFullYear(),
        new Date().getUTCMonth(),
        new Date().getUTCDate() - days + 1,
      ),
    );
    const [created, high] = await Promise.all([
      this.scannedDomains.newPerDay(since, originalDomainId),
      this.prisma.$queryRaw<{ day: Date; count: bigint }[]>`
        SELECT date_trunc('day', a.computed_at AT TIME ZONE 'UTC') AS day, count(DISTINCT a.scanned_domain_id) AS count
        FROM analytics a JOIN scanned_domains s ON s.id = a.scanned_domain_id
        WHERE a.threat_level = 'HIGH_RISK' AND a.computed_at >= ${since} AND s.deleted_at IS NULL
          AND (${originalDomainId ?? null}::uuid IS NULL OR s.original_domain_id = ${originalDomainId ?? null}::uuid)
        GROUP BY 1 ORDER BY 1`,
    ]);
    const createdByDay = new Map(
      created.map((r) => [day(r.day), Number(r.count)]),
    );
    const highByDay = new Map(high.map((r) => [day(r.day), Number(r.count)]));
    return Array.from({ length: days }, (_, i) => {
      const date = day(new Date(since.getTime() + i * 86_400_000));
      return {
        date,
        newLookalikes: createdByDay.get(date) ?? 0,
        highRisk: highByDay.get(date) ?? 0,
      };
    });
  }
}
