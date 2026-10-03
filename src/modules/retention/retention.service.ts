import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Redis } from 'ioredis';
import { TransactionalEventBus } from '../../common/events/transactional-event-bus.js';
import type { AppConfig } from '../../config/configuration.js';
import { Prisma } from '../../database/generated/prisma/client.js';
import {
  PrismaService,
  type PrismaTransaction,
} from '../../database/prisma.service.js';
import { REDIS_CLIENT } from '../../redis/redis.module.js';
import { StorageService } from '../../storage/storage.service.js';
import {
  RetentionBeforePurgeEvent,
  RetentionPurgedEvent,
  type RetentionTable,
} from './events/retention.events.js';
import { RetentionLock } from './retention.lock.js';

export interface RetentionReport {
  requestedBy: string;
  startedAt: string;
  finishedAt: string;
  cutoff: string;
  keepLatest: boolean;
  /** Rows removed per table (children removed by ON DELETE CASCADE are not counted). */
  rows: Partial<Record<RetentionTable, number>>;
  objectsDeleted: number;
  /** Objects S3 refused to delete; their rows were kept and are retried next run. */
  objectsFailed: number;
}

export interface SweepReport {
  requestedBy: string;
  startedAt: string;
  finishedAt: string;
  scanned: number;
  orphans: number;
  deleted: number;
  failed: number;
}

export const LAST_RUN_KEY = 'retention:last-run';
export const LAST_SWEEP_KEY = 'retention:last-sweep';
const LOCK_TTL_MS = 6 * 3_600_000;
const NIL_UUID = '00000000-0000-0000-0000-000000000000';
/** Soft-deleted parents are purged in smaller batches: each one cascades to many children. */
const PARENT_BATCH = 200;

/**
 * 31-day data retention (PLAN.md §6a). Every batch is its own short transaction through the
 * event bus, so a run can be interrupted at any point and simply re-run. Object-storage deletes
 * always happen BEFORE the rows that reference them; a row whose object could not be deleted is
 * kept for the next run, so nothing is ever orphaned by retention itself.
 */
@Injectable()
export class RetentionService {
  private readonly logger = new Logger(RetentionService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: TransactionalEventBus,
    private readonly storage: StorageService,
    private readonly lock: RetentionLock,
    private readonly config: ConfigService<AppConfig, true>,
    @Inject(REDIS_CLIENT) private readonly redis: Redis,
  ) {}

  private get settings() {
    return this.config.get('retention', { infer: true });
  }

  /** Runs retention unless another run holds the lock (returns null then). */
  run(requestedBy: string, now = new Date()): Promise<RetentionReport | null> {
    return this.lock.withLock('retention', LOCK_TTL_MS, () =>
      this.runUnlocked(requestedBy, now),
    );
  }

  async lastRun(): Promise<RetentionReport | null> {
    return this.read<RetentionReport>(LAST_RUN_KEY);
  }

  async lastSweep(): Promise<SweepReport | null> {
    return this.read<SweepReport>(LAST_SWEEP_KEY);
  }

  private async read<T>(key: string): Promise<T | null> {
    const raw = await this.redis.get(key).catch(() => null);
    return raw ? (JSON.parse(raw) as T) : null;
  }

  private async runUnlocked(
    requestedBy: string,
    now: Date,
  ): Promise<RetentionReport> {
    const { days, keepLatest } = this.settings;
    const cutoff = new Date(now.getTime() - days * 86_400_000);
    const report: RetentionReport = {
      requestedBy,
      startedAt: new Date().toISOString(),
      finishedAt: '',
      cutoff: cutoff.toISOString(),
      keepLatest,
      rows: {},
      objectsDeleted: 0,
      objectsFailed: 0,
    };
    this.logger.log(
      `Retention started (cutoff ${report.cutoff}, keepLatest=${keepLatest}, by ${requestedBy})`,
    );

    // Children first, then parents: fewer rows for the cascades to touch.
    await this.purgeScreenshots(cutoff, keepLatest, report);
    await this.purgeHistory('analytics', cutoff, keepLatest, report);
    await this.purgeHistory('whois_informations', cutoff, keepLatest, report);
    await this.purgeScans(cutoff, keepLatest, report);
    await this.purgeDeleted('scanned_domains', cutoff, report);
    await this.purgeDeleted('original_domains', cutoff, report);
    await this.purgeDeadLetters(cutoff, report);
    await this.purgeAlertDeliveries(cutoff, report);

    report.finishedAt = new Date().toISOString();
    await this.redis
      .set(LAST_RUN_KEY, JSON.stringify(report))
      .catch(() => undefined);
    this.logger.log(
      `Retention finished: ${JSON.stringify(report.rows)}; objects deleted ${report.objectsDeleted}, failed ${report.objectsFailed}`,
    );
    return report;
  }

  /** One batch = one transaction with before/after events. Returns rows deleted. */
  private async batch(
    table: RetentionTable,
    cutoff: Date,
    size: number,
    work: (tx: PrismaTransaction) => Promise<number>,
    objects = 0,
  ): Promise<number> {
    return this.bus.write({
      before: new RetentionBeforePurgeEvent(table, cutoff.toISOString(), size),
      work: async (tx, after) => {
        const n = await work(tx);
        if (n > 0) after.add(new RetentionPurgedEvent(table, n, objects));
        return n;
      },
      timeoutMs: 60_000,
    });
  }

  private count(report: RetentionReport, table: RetentionTable, n: number) {
    report.rows[table] = (report.rows[table] ?? 0) + n;
  }

  /** Deletes objects; returns the keys that are confirmed gone (missing keys count as gone). */
  private async deleteObjects(
    keys: string[],
    report: RetentionReport,
  ): Promise<Set<string>> {
    if (!keys.length) return new Set();
    try {
      const { deleted, failed } = await this.storage.deleteObjects(keys);
      report.objectsDeleted += deleted.length;
      report.objectsFailed += failed.length;
      const failedSet = new Set(failed);
      return new Set(keys.filter((k) => !failedSet.has(k)));
    } catch (e) {
      this.logger.warn(
        `Object storage delete failed for ${keys.length} key(s): ${(e as Error).message}`,
      );
      report.objectsFailed += keys.length;
      return new Set();
    }
  }

  private async purgeScreenshots(
    cutoff: Date,
    keepLatest: boolean,
    report: RetentionReport,
  ) {
    const size = this.settings.batchSize;
    let cursor = NIL_UUID;
    for (;;) {
      // Keyset by id so rows kept because of a failed object delete are not re-read forever.
      const candidates = await this.prisma.$queryRaw<
        { id: string; storage_key: string | null }[]
      >`
        SELECT s.id, s.storage_key FROM screenshots s
         WHERE s.created_at < ${cutoff} AND s.id > ${cursor}::uuid
           AND (${!keepLatest} OR s.status <> 'CAPTURED'::"ScreenshotStatus" OR EXISTS (
                 SELECT 1 FROM screenshots n
                  WHERE n.scanned_domain_id = s.scanned_domain_id
                    AND n.status = 'CAPTURED'::"ScreenshotStatus"
                    AND (n.created_at, n.id) > (s.created_at, s.id)))
         ORDER BY s.id
         LIMIT ${size}`;
      if (!candidates.length) return;
      cursor = candidates[candidates.length - 1].id;

      const keys = candidates
        .map((c) => c.storage_key)
        .filter((k): k is string => !!k);
      const gone = await this.deleteObjects(keys, report);
      const ids = candidates
        .filter((c) => !c.storage_key || gone.has(c.storage_key))
        .map((c) => c.id);
      if (ids.length) {
        const n = await this.batch(
          'screenshots',
          cutoff,
          size,
          (tx) =>
            tx.$executeRaw`DELETE FROM screenshots WHERE id = ANY(${ids}::uuid[])`,
          gone.size,
        );
        this.count(report, 'screenshots', n);
      }
      if (candidates.length < size) return;
    }
  }

  /** analytics / whois_informations: older than the cutoff, except each domain's newest row. */
  private async purgeHistory(
    table: 'analytics' | 'whois_informations',
    cutoff: Date,
    keepLatest: boolean,
    report: RetentionReport,
  ) {
    const size = this.settings.batchSize;
    const t = Prisma.raw(table);
    const at = Prisma.raw(table === 'analytics' ? 'computed_at' : 'fetched_at');
    for (;;) {
      const n = await this.batch(
        table,
        cutoff,
        size,
        (tx) => tx.$executeRaw`
        DELETE FROM ${t} WHERE id IN (
          SELECT h.id FROM ${t} h
           WHERE h.${at} < ${cutoff}
             AND (${!keepLatest} OR EXISTS (
                   SELECT 1 FROM ${t} n
                    WHERE n.scanned_domain_id = h.scanned_domain_id
                      AND (n.${at}, n.id) > (h.${at}, h.id)))
           LIMIT ${size})`,
      );
      this.count(report, table, n);
      if (n < size) return;
    }
  }

  /** Finished scans older than the cutoff (FKs on look-alikes / history are SET NULL). */
  private async purgeScans(
    cutoff: Date,
    keepLatest: boolean,
    report: RetentionReport,
  ) {
    const size = this.settings.batchSize;
    for (;;) {
      const n = await this.batch(
        'scans',
        cutoff,
        size,
        (tx) => tx.$executeRaw`
        DELETE FROM scans WHERE id IN (
          SELECT s.id FROM scans s
           WHERE s.created_at < ${cutoff}
             AND s.status IN ('COMPLETED'::"ScanStatus", 'FAILED'::"ScanStatus", 'CANCELLED'::"ScanStatus")
             AND (${!keepLatest} OR EXISTS (
                   SELECT 1 FROM scans n
                    WHERE n.original_domain_id = s.original_domain_id
                      AND (n.created_at, n.id) > (s.created_at, s.id)))
           LIMIT ${size})`,
      );
      this.count(report, 'scans', n);
      if (n < size) return;
    }
  }

  /**
   * Hard-purges rows soft-deleted before the cutoff. Their screenshot objects are collected and
   * deleted first; a parent with an undeletable object is skipped until the next run.
   */
  private async purgeDeleted(
    table: 'scanned_domains' | 'original_domains',
    cutoff: Date,
    report: RetentionReport,
  ) {
    const t = Prisma.raw(table);
    let cursor = NIL_UUID;
    for (;;) {
      const parents = await this.prisma.$queryRaw<{ id: string }[]>`
        SELECT id FROM ${t} WHERE deleted_at < ${cutoff} AND id > ${cursor}::uuid
         ORDER BY id LIMIT ${PARENT_BATCH}`;
      if (!parents.length) return;
      cursor = parents[parents.length - 1].id;
      const ids = parents.map((p) => p.id);

      const objects =
        table === 'scanned_domains'
          ? await this.prisma.$queryRaw<{ parent: string; key: string }[]>`
              SELECT scanned_domain_id AS parent, storage_key AS key FROM screenshots
               WHERE scanned_domain_id = ANY(${ids}::uuid[]) AND storage_key IS NOT NULL`
          : await this.prisma.$queryRaw<{ parent: string; key: string }[]>`
              SELECT d.original_domain_id AS parent, s.storage_key AS key
                FROM screenshots s JOIN scanned_domains d ON d.id = s.scanned_domain_id
               WHERE d.original_domain_id = ANY(${ids}::uuid[]) AND s.storage_key IS NOT NULL
              UNION ALL
              SELECT original_domain_id AS parent, storage_key AS key FROM brand_references
               WHERE original_domain_id = ANY(${ids}::uuid[]) AND storage_key IS NOT NULL`;
      const gone = await this.deleteObjects(
        objects.map((o) => o.key),
        report,
      );
      const blocked = new Set(
        objects.filter((o) => !gone.has(o.key)).map((o) => o.parent),
      );
      const purge = ids.filter((id) => !blocked.has(id));
      if (purge.length) {
        const n = await this.batch(
          table,
          cutoff,
          PARENT_BATCH,
          (tx) =>
            tx.$executeRaw`DELETE FROM ${t} WHERE id = ANY(${purge}::uuid[]) AND deleted_at IS NOT NULL`,
          gone.size,
        );
        this.count(report, table, n);
      }
      if (parents.length < PARENT_BATCH) return;
    }
  }

  /** Dead-lettered outbox rows are kept for inspection for the retention period. */
  private async purgeDeadLetters(cutoff: Date, report: RetentionReport) {
    const size = this.settings.batchSize;
    for (;;) {
      const n = await this.batch(
        'outbox_events',
        cutoff,
        size,
        (tx) => tx.$executeRaw`
        DELETE FROM outbox_events WHERE id IN (
          SELECT id FROM outbox_events WHERE failed_at < ${cutoff} LIMIT ${size})`,
      );
      this.count(report, 'outbox_events', n);
      if (n < size) return;
    }
  }

  /** Sent / failed alert deliveries older than the cutoff (pending ones are never dropped). */
  private async purgeAlertDeliveries(cutoff: Date, report: RetentionReport) {
    const size = this.settings.batchSize;
    for (;;) {
      const n = await this.batch(
        'alert_deliveries',
        cutoff,
        size,
        (tx) => tx.$executeRaw`
        DELETE FROM alert_deliveries WHERE id IN (
          SELECT id FROM alert_deliveries
           WHERE created_at < ${cutoff} AND status <> 'PENDING'::"AlertDeliveryStatus"
           LIMIT ${size})`,
      );
      this.count(report, 'alert_deliveries', n);
      if (n < size) return;
    }
  }

  /**
   * Weekly backstop: removes objects under `screenshots/` that no row references (e.g. an upload
   * whose transaction rolled back and whose compensating delete also failed).
   */
  sweepOrphans(requestedBy: string): Promise<SweepReport | null> {
    return this.lock.withLock('orphan-sweep', LOCK_TTL_MS, async () => {
      const report: SweepReport = {
        requestedBy,
        startedAt: new Date().toISOString(),
        finishedAt: '',
        scanned: 0,
        orphans: 0,
        deleted: 0,
        failed: 0,
      };
      // Objects younger than this are never orphans: uploads happen before the row commits.
      const youngest = Date.now() - this.settings.orphanMinAgeMs;
      for await (const page of this.storage.listObjects('screenshots/')) {
        report.scanned += page.length;
        const keys = page
          .filter((o) => o.lastModified.getTime() < youngest)
          .map((o) => o.key);
        if (!keys.length) continue;
        const known = await this.prisma.screenshot.findMany({
          where: { storageKey: { in: keys } },
          select: { storageKey: true },
        });
        const referenced = new Set(known.map((k) => k.storageKey));
        const orphans = keys.filter((k) => !referenced.has(k));
        if (!orphans.length) continue;
        report.orphans += orphans.length;
        try {
          const { deleted, failed } = await this.storage.deleteObjects(orphans);
          report.deleted += deleted.length;
          report.failed += failed.length;
        } catch (e) {
          report.failed += orphans.length;
          this.logger.warn(`Orphan delete failed: ${(e as Error).message}`);
        }
      }
      report.finishedAt = new Date().toISOString();
      await this.redis
        .set(LAST_SWEEP_KEY, JSON.stringify(report))
        .catch(() => undefined);
      this.logger.log(
        `Orphan sweep: ${report.scanned} objects scanned, ${report.deleted}/${report.orphans} orphans deleted`,
      );
      return report;
    });
  }
}
