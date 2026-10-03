import { domainToUnicode } from 'node:url';
import { Injectable } from '@nestjs/common';
import { TransactionalEventBus } from '../../common/events/transactional-event-bus.js';
import { PrismaService } from '../../database/prisma.service.js';
import { Prisma } from '../../database/generated/prisma/client.js';
import type { DnsResolution } from '../dns-resolver/dns.types.js';
import type { EnrichmentFlags } from '../scans/events/scan.events.js';
import {
  DomainStatus,
  type ThreatLevel,
} from '../../database/generated/prisma/enums.js';
import type { StatusChangeSource } from './status-rules.js';
import {
  ScannedDomainBeforeDeleteEvent,
  ScannedDomainBeforeStatusChangeEvent,
  ScannedDomainBeforeTagsUpdateEvent,
  ScannedDomainDeletedEvent,
  ScannedDomainStatusChangedEvent,
  ScannedDomainTagsUpdatedEvent,
  ScannedDomainBatchUpsertedEvent,
  ScannedDomainBeforeRiskUpdateEvent,
  ScannedDomainRiskUpdatedEvent,
  ScannedDomainBeforeMarkInactiveEvent,
  ScannedDomainBeforeUpsertEvent,
  ScannedDomainDiscoveredEvent,
  ScannedDomainMarkedInactiveEvent,
  ScannedDomainUpdatedEvent,
} from './events/scanned-domain.events.js';

export interface UpsertBatchInput {
  /** Omitted for sightings outside a scan (CT monitoring): an existing last_scan_id is kept. */
  scanId?: string;
  originalDomainId: string;
  /** permutation domain → fuzzer technique that produced it */
  fuzzerByDomain: Record<string, string>;
  /** Only registered resolutions are persisted. */
  resolutions: DnsResolution[];
  enrichment?: EnrichmentFlags;
}

export interface UpsertBatchResult {
  inserted: number;
  updated: number;
}

const DNS_FIELDS = ['dnsA', 'dnsAaaa', 'dnsMx', 'dnsNs'] as const;
const sameSet = (a: string[] | null | undefined, b: string[]) =>
  [...(a ?? [])].sort().join(',') === [...b].sort().join(',');

/** Writes for scanned_domains. Every write goes through TransactionalEventBus. */
@Injectable()
export class ScannedDomainsService {
  constructor(
    private readonly bus: TransactionalEventBus,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * One multi-row `INSERT … ON CONFLICT (original_domain_id, domain) DO UPDATE` per DNS batch.
   * New rows start as NEW; rows seen again refresh DNS + last_seen_at and move NEW/INACTIVE to
   * ACTIVE. Analyst-driven statuses (UNDER_REVIEW, CONFIRMED_THREAT, …) and soft-deletes are kept.
   */
  async upsertBatch(input: UpsertBatchInput): Promise<UpsertBatchResult> {
    const registered = input.resolutions.filter((r) => r.registered);
    if (registered.length === 0) return { inserted: 0, updated: 0 };
    const domains = registered.map((r) => r.domain);

    return this.bus.write({
      before: new ScannedDomainBeforeUpsertEvent(
        input.originalDomainId,
        input.scanId,
        domains,
      ),
      work: async (tx, after) => {
        const previous = new Map(
          (
            await tx.scannedDomain.findMany({
              where: {
                originalDomainId: input.originalDomainId,
                domain: { in: domains },
              },
              select: {
                domain: true,
                dnsA: true,
                dnsAaaa: true,
                dnsMx: true,
                dnsNs: true,
                threatLevel: true,
              },
            })
          ).map((row) => [row.domain, row]),
        );

        const values = registered.map(
          (r) => Prisma.sql`(
            ${input.originalDomainId}::uuid, ${input.scanId ?? null}::uuid, ${r.domain}, ${domainToUnicode(r.domain) || r.domain},
            ${input.fuzzerByDomain[r.domain] ?? 'unknown'}, ${r.a}::text[], ${r.aaaa}::text[], ${r.mx}::text[],
            ${r.ns}::text[], ${r.ttl}::int, ${r.errors}::text[], now()
          )`,
        );

        const rows = await tx.$queryRaw<
          { id: string; domain: string; inserted: boolean; deleted: boolean }[]
        >`
          INSERT INTO scanned_domains (
            original_domain_id, last_scan_id, domain, unicode_domain, fuzzer,
            dns_a, dns_aaaa, dns_mx, dns_ns, dns_ttl, dns_errors, updated_at
          )
          VALUES ${Prisma.join(values)}
          ON CONFLICT (original_domain_id, domain) DO UPDATE SET
            last_scan_id = COALESCE(EXCLUDED.last_scan_id, scanned_domains.last_scan_id),
            dns_a = EXCLUDED.dns_a,
            dns_aaaa = EXCLUDED.dns_aaaa,
            dns_mx = EXCLUDED.dns_mx,
            dns_ns = EXCLUDED.dns_ns,
            dns_ttl = EXCLUDED.dns_ttl,
            dns_errors = EXCLUDED.dns_errors,
            last_seen_at = now(),
            updated_at = now(),
            status = CASE
              WHEN scanned_domains.status = 'INACTIVE' THEN 'ACTIVE'::"DomainStatus"
              WHEN scanned_domains.status = 'NEW'
                AND scanned_domains.last_scan_id IS DISTINCT FROM EXCLUDED.last_scan_id THEN 'ACTIVE'::"DomainStatus"
              ELSE scanned_domains.status
            END
          RETURNING id, domain, (xmax = 0) AS inserted, (deleted_at IS NOT NULL) AS deleted`;

        const byDomain = new Map(registered.map((r) => [r.domain, r]));
        const enrichment = input.enrichment ?? {
          whois: true,
          screenshots: true,
        };
        let inserted = 0;
        let updated = 0;
        for (const row of rows) {
          const resolution = byDomain.get(row.domain)!;
          if (row.inserted) {
            inserted++;
            after.add(
              new ScannedDomainDiscoveredEvent(
                row.id,
                input.originalDomainId,
                input.scanId,
                row.domain,
                resolution.a.length > 0 || resolution.aaaa.length > 0,
                enrichment,
              ),
            );
            continue;
          }
          updated++;
          const before = previous.get(row.domain);
          const now = {
            dnsA: resolution.a,
            dnsAaaa: resolution.aaaa,
            dnsMx: resolution.mx,
            dnsNs: resolution.ns,
          };
          const changed = DNS_FIELDS.filter(
            (f) => !sameSet(before?.[f], now[f]),
          );
          const neverScored = before?.threatLevel === 'UNSCORED';
          if ((changed.length > 0 || neverScored) && !row.deleted) {
            after.add(
              new ScannedDomainUpdatedEvent(
                row.id,
                input.originalDomainId,
                input.scanId,
                row.domain,
                changed,
                resolution.a.length > 0 || resolution.aaaa.length > 0,
                enrichment,
                neverScored,
              ),
            );
          }
        }
        if (input.scanId)
          after.add(
            new ScannedDomainBatchUpsertedEvent(
              input.scanId,
              inserted,
              updated,
            ),
          );
        return { inserted, updated };
      },
    });
  }

  /** Mirrors the latest analytics result onto the look-alike (risk_score / threat_level). */
  async updateRisk(
    scannedDomainId: string,
    riskScore: number,
    threatLevel: ThreatLevel,
  ): Promise<boolean> {
    return this.bus.write({
      before: new ScannedDomainBeforeRiskUpdateEvent(
        scannedDomainId,
        riskScore,
        threatLevel,
      ),
      work: async (tx, after) => {
        const current = await tx.scannedDomain.findUnique({
          where: { id: scannedDomainId },
          select: { threatLevel: true },
        });
        if (!current) return false;
        await tx.scannedDomain.update({
          where: { id: scannedDomainId },
          data: { riskScore, threatLevel },
        });
        after.add(
          new ScannedDomainRiskUpdatedEvent(
            scannedDomainId,
            riskScore,
            threatLevel,
            current.threatLevel,
          ),
        );
        return true;
      },
    });
  }

  /**
   * After a FULL scan: look-alikes that were not seen are no longer registered → INACTIVE.
   * Only system-managed statuses are touched; analyst decisions are preserved.
   */
  async markUnseenInactive(
    originalDomainId: string,
    scanId: string,
  ): Promise<string[]> {
    return this.bus.write({
      before: new ScannedDomainBeforeMarkInactiveEvent(
        originalDomainId,
        scanId,
      ),
      work: async (tx, after) => {
        const rows = await tx.$queryRaw<{ id: string }[]>`
          UPDATE scanned_domains
          SET status = 'INACTIVE'::"DomainStatus", updated_at = now()
          WHERE original_domain_id = ${originalDomainId}::uuid
            AND deleted_at IS NULL
            AND status IN ('NEW', 'ACTIVE', 'PARKED')
            AND last_scan_id IS DISTINCT FROM ${scanId}::uuid
          RETURNING id`;
        const ids = rows.map((r) => r.id);
        if (ids.length)
          after.add(
            new ScannedDomainMarkedInactiveEvent(originalDomainId, scanId, ids),
          );
        return ids;
      },
    });
  }

  /**
   * Sets the status of one or many look-alikes in one transaction. The before-event is
   * validated by StatusRulesListener (422 on any disallowed transition — nothing changes).
   */
  async changeStatus(
    ids: string[],
    to: DomainStatus,
    ctx: { source: StatusChangeSource; actor: string },
  ): Promise<{ changed: number; unchanged: number }> {
    return this.bus.write({
      before: new ScannedDomainBeforeStatusChangeEvent(
        ids,
        to,
        ctx.source,
        ctx.actor,
      ),
      work: async (tx, after) => {
        const rows = await tx.scannedDomain.findMany({
          where: { id: { in: ids }, deletedAt: null },
          select: {
            id: true,
            originalDomainId: true,
            domain: true,
            status: true,
          },
        });
        let changed = 0;
        for (const row of rows) {
          if (row.status === to) continue;
          // Compare-and-set: skip if another writer moved it since we read it.
          const { count } = await tx.scannedDomain.updateMany({
            where: { id: row.id, status: row.status },
            data: { status: to },
          });
          if (!count) continue;
          changed++;
          after.add(
            new ScannedDomainStatusChangedEvent(
              row.id,
              row.originalDomainId,
              row.domain,
              row.status,
              to,
              ctx.source,
              ctx.actor,
            ),
          );
        }
        return { changed, unchanged: ids.length - changed };
      },
    });
  }

  /** Adds/removes tags (normalised: lower-case, trimmed, de-duplicated, max 50 per domain). */
  async updateTags(
    ids: string[],
    change: { add?: string[]; remove?: string[] },
    actor: string,
  ): Promise<number> {
    const norm = (t: string[] = []) => [
      ...new Set(t.map((x) => x.trim().toLowerCase()).filter(Boolean)),
    ];
    const add = norm(change.add);
    const remove = new Set(norm(change.remove));
    return this.bus.write({
      before: new ScannedDomainBeforeTagsUpdateEvent(ids, add, [...remove]),
      work: async (tx, after) => {
        const rows = await tx.scannedDomain.findMany({
          where: { id: { in: ids }, deletedAt: null },
          select: { id: true, tags: true },
        });
        const touched: string[] = [];
        for (const row of rows) {
          const current = row.tags ?? [];
          const next = [
            ...new Set([...current.filter((t) => !remove.has(t)), ...add]),
          ].slice(0, 50);
          if (next.join('\u0000') === current.join('\u0000')) continue;
          await tx.scannedDomain.update({
            where: { id: row.id },
            data: { tags: next },
          });
          touched.push(row.id);
        }
        if (touched.length)
          after.add(new ScannedDomainTagsUpdatedEvent(touched, actor));
        return touched.length;
      },
    });
  }

  /** Soft delete: hidden from lists and enrichment; the row (and its history) is kept until retention purges it. */
  async softDelete(id: string, actor: string): Promise<boolean> {
    return this.bus.write({
      before: new ScannedDomainBeforeDeleteEvent(id),
      work: async (tx, after) => {
        const row = await tx.scannedDomain.findFirst({
          where: { id, deletedAt: null },
          select: { domain: true },
        });
        if (!row) return false;
        await tx.scannedDomain.update({
          where: { id },
          data: { deletedAt: new Date() },
        });
        after.add(new ScannedDomainDeletedEvent(id, row.domain, actor));
        return true;
      },
    });
  }

  /**
   * Manual rescan of one look-alike: refreshes DNS and forces WHOIS/screenshot/scoring.
   * If it no longer resolves, a system-managed status becomes INACTIVE.
   */
  async refreshDns(
    id: string,
    resolution: DnsResolution,
    actor: string,
  ): Promise<'refreshed' | 'inactive' | 'gone'> {
    const current = await this.prisma.scannedDomain.findFirst({
      where: { id, deletedAt: null },
      select: { originalDomainId: true, lastScanId: true, status: true },
    });
    if (!current) return 'gone';
    if (!resolution.registered) {
      if (SYSTEM_STATUSES_FOR_INACTIVE.includes(current.status)) {
        await this.changeStatus([id], DomainStatus.INACTIVE, {
          source: 'system',
          actor,
        });
      }
      return 'inactive';
    }
    return this.bus.write({
      before: new ScannedDomainBeforeUpsertEvent(
        current.originalDomainId,
        current.lastScanId ?? undefined,
        [resolution.domain],
      ),
      work: async (tx, after) => {
        const before = await tx.scannedDomain.findFirst({
          where: { id, deletedAt: null },
        });
        if (!before) return 'gone' as const;
        const reactivate = before.status === DomainStatus.INACTIVE;
        await tx.scannedDomain.update({
          where: { id },
          data: {
            dnsA: resolution.a,
            dnsAaaa: resolution.aaaa,
            dnsMx: resolution.mx,
            dnsNs: resolution.ns,
            dnsTtl: resolution.ttl,
            dnsErrors: resolution.errors,
            lastSeenAt: new Date(),
            ...(reactivate ? { status: DomainStatus.ACTIVE } : {}),
          },
        });
        const now = {
          dnsA: resolution.a,
          dnsAaaa: resolution.aaaa,
          dnsMx: resolution.mx,
          dnsNs: resolution.ns,
        };
        const changed = DNS_FIELDS.filter((f) => !sameSet(before[f], now[f]));
        after.add(
          new ScannedDomainUpdatedEvent(
            id,
            before.originalDomainId,
            before.lastScanId ?? undefined,
            before.domain,
            changed,
            resolution.a.length > 0 || resolution.aaaa.length > 0,
            { whois: true, screenshots: true },
            false,
            true,
          ),
        );
        if (reactivate) {
          after.add(
            new ScannedDomainStatusChangedEvent(
              id,
              before.originalDomainId,
              before.domain,
              before.status,
              DomainStatus.ACTIVE,
              'system',
              actor,
            ),
          );
        }
        return 'refreshed' as const;
      },
    });
  }
}

const SYSTEM_STATUSES_FOR_INACTIVE: DomainStatus[] = [
  DomainStatus.NEW,
  DomainStatus.ACTIVE,
  DomainStatus.PARKED,
];
