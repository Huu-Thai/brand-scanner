import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service.js';

/** Read-only access for other modules. */
@Injectable()
export class ScannedDomainsQuery {
  constructor(private readonly prisma: PrismaService) {}

  /** Everything enrichment/scoring needs about one look-alike (null if missing or soft-deleted). */
  getForEnrichment(id: string) {
    return this.prisma.scannedDomain.findFirst({
      where: { id, deletedAt: null },
      select: {
        id: true,
        domain: true,
        originalDomainId: true,
        fuzzer: true,
        status: true,
        riskScore: true,
        unicodeDomain: true,
        threatLevel: true,
        dnsA: true,
        dnsAaaa: true,
        dnsMx: true,
        dnsNs: true,
        dnsTtl: true,
        originalDomain: { select: { domain: true } },
      },
    });
  }

  /** Authoritative scan totals, computed from the rows themselves (not from event counters). */
  async countsForScan(
    scanId: string,
    startedAt: Date | null,
  ): Promise<{ registeredCount: number; newCount: number }> {
    const [registeredCount, newCount] = await Promise.all([
      this.prisma.scannedDomain.count({ where: { lastScanId: scanId } }),
      startedAt
        ? this.prisma.scannedDomain.count({
            where: { lastScanId: scanId, firstSeenAt: { gte: startedAt } },
          })
        : Promise.resolve(0),
    ]);
    return { registeredCount, newCount };
  }

  /** Look-alike counts per threat level / status / technique for one brand (or all). */
  async summary(originalDomainId?: string) {
    const where = {
      deletedAt: null,
      ...(originalDomainId ? { originalDomainId } : {}),
    };
    const [byThreatLevel, byStatus, byFuzzer, total] = await Promise.all([
      this.prisma.scannedDomain.groupBy({
        by: ['threatLevel'],
        where,
        _count: { _all: true },
      }),
      this.prisma.scannedDomain.groupBy({
        by: ['status'],
        where,
        _count: { _all: true },
      }),
      this.prisma.scannedDomain.groupBy({
        by: ['fuzzer'],
        where,
        _count: { _all: true },
      }),
      this.prisma.scannedDomain.count({ where }),
    ]);
    const toMap = <K extends string>(
      rows: ({ _count: { _all: number } } & Record<string, unknown>)[],
      key: K,
    ) => Object.fromEntries(rows.map((r) => [r[key] as string, r._count._all]));
    return {
      total,
      byThreatLevel: toMap(byThreatLevel, 'threatLevel'),
      byStatus: toMap(byStatus, 'status'),
      byFuzzer: toMap(byFuzzer, 'fuzzer'),
    };
  }

  /** New look-alikes per UTC day. */
  newPerDay(since: Date, originalDomainId?: string) {
    return this.prisma.$queryRaw<{ day: Date; count: bigint }[]>`
      SELECT date_trunc('day', first_seen_at AT TIME ZONE 'UTC') AS day, count(*) AS count
      FROM scanned_domains
      WHERE deleted_at IS NULL AND first_seen_at >= ${since}
        AND (${originalDomainId ?? null}::uuid IS NULL OR original_domain_id = ${originalDomainId ?? null}::uuid)
      GROUP BY 1 ORDER BY 1`;
  }

  /** Look-alikes found by CT monitoring for a brand, re-resolved by every full scan. */
  async ctDomains(originalDomainId: string): Promise<[string, string][]> {
    const rows = await this.prisma.scannedDomain.findMany({
      where: {
        originalDomainId,
        deletedAt: null,
        fuzzer: { startsWith: 'ct:' },
      },
      select: { domain: true, fuzzer: true },
    });
    return rows.map((r) => [r.domain, r.fuzzer]);
  }
}
