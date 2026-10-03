import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { type Paginated, paginated } from '../../common/dto/pagination.dto.js';
import { TransactionalEventBus } from '../../common/events/transactional-event-bus.js';
import { constraintFromMeta } from '../../database/constraints.js';
import { Prisma } from '../../database/generated/prisma/client.js';
import {
  ScanStatus,
  type ScanTrigger,
} from '../../database/generated/prisma/enums.js';
import type { ScanModel } from '../../database/generated/prisma/models.js';
import { PrismaService } from '../../database/prisma.service.js';
import { OriginalDomainsQuery } from '../original-domains/original-domains.query.js';
import type { ListScansQueryDto, ScanDto } from './dto/scan.dto.js';
import {
  type ScanCounts,
  ScanBeforeCreateEvent,
  ScanBeforeProgressEvent,
  ScanBeforeStatusChangeEvent,
  ScanCreatedEvent,
  ScanFinishedEvent,
  type ScanOptions,
  ScanProgressEvent,
  ScanStatusChangedEvent,
  SCAN_EVENTS,
} from './events/scan.events.js';
import { toScanDto } from './scans.mapper.js';

export const ACTIVE_SCAN_STATUSES: ScanStatus[] = [
  ScanStatus.QUEUED,
  ScanStatus.FUZZING,
  ScanStatus.RESOLVING,
  ScanStatus.ENRICHING,
];

export interface CreateScanInput {
  originalDomainId: string;
  triggeredBy: ScanTrigger;
  options?: ScanOptions;
  idempotencyKey?: string;
}

export interface CreateScanResult {
  scan: ScanModel;
  /** False when an in-flight scan or an idempotent replay was returned instead. */
  created: boolean;
}

const FINISHED_EVENT: Partial<Record<ScanStatus, ScanFinishedEvent['name']>> = {
  [ScanStatus.COMPLETED]: SCAN_EVENTS.COMPLETED,
  [ScanStatus.FAILED]: SCAN_EVENTS.FAILED,
  [ScanStatus.CANCELLED]: SCAN_EVENTS.CANCELLED,
};

const isFullScan = (options: unknown) =>
  !((options as ScanOptions | null)?.fuzzers?.length ?? 0);

@Injectable()
export class ScansService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: TransactionalEventBus,
    private readonly originalDomains: OriginalDomainsQuery,
  ) {}

  /**
   * Starts a scan, or returns the one already in flight for the domain. Concurrency is
   * settled by the `uq_scans_active_original_domain` partial unique index, not by this code.
   */
  async create(input: CreateScanInput): Promise<CreateScanResult> {
    if (input.idempotencyKey) {
      const replay = await this.prisma.scan.findUnique({
        where: { idempotencyKey: input.idempotencyKey },
      });
      if (replay) return this.replay(replay, input.originalDomainId);
    }

    const original = await this.originalDomains.getScannable(
      input.originalDomainId,
    );
    const options: ScanOptions = {
      ...(original.scanOptions as ScanOptions),
      ...input.options,
    };

    try {
      return await this.bus.write({
        before: new ScanBeforeCreateEvent(
          original.id,
          input.triggeredBy,
          options,
        ),
        work: async (tx, after) => {
          const active = await tx.scan.findFirst({
            where: {
              originalDomainId: original.id,
              status: { in: ACTIVE_SCAN_STATUSES },
            },
          });
          if (active) return { scan: active, created: false };
          const scan = await tx.scan.create({
            data: {
              originalDomainId: original.id,
              triggeredBy: input.triggeredBy,
              options: options as Prisma.InputJsonValue,
              idempotencyKey: input.idempotencyKey,
            },
          });
          after.add(
            new ScanCreatedEvent(
              scan.id,
              scan.originalDomainId,
              scan.triggeredBy,
            ),
          );
          return { scan, created: true };
        },
      });
    } catch (e) {
      // Lost a race: another request created the active scan / used the key between our check and insert.
      if (
        e instanceof Prisma.PrismaClientKnownRequestError &&
        e.code === 'P2002'
      ) {
        const constraint = constraintFromMeta(e.meta);
        const winner =
          constraint === 'uq_scans_idempotency_key' && input.idempotencyKey
            ? await this.prisma.scan.findUnique({
                where: { idempotencyKey: input.idempotencyKey },
              })
            : await this.prisma.scan.findFirst({
                where: {
                  originalDomainId: original.id,
                  status: { in: ACTIVE_SCAN_STATUSES },
                },
              });
        if (winner) return { scan: winner, created: false };
      }
      throw e;
    }
  }

  async findAll(query: ListScansQueryDto): Promise<Paginated<ScanDto>> {
    const where: Prisma.ScanWhereInput = {
      originalDomainId: query.originalDomainId,
      status: query.status?.length ? { in: query.status } : undefined,
      createdAt:
        query.from || query.to ? { gte: query.from, lt: query.to } : undefined,
    };
    const [rows, total] = await Promise.all([
      this.prisma.scan.findMany({
        where,
        orderBy: { createdAt: query.order },
        skip: query.skip,
        take: query.limit,
      }),
      this.prisma.scan.count({ where }),
    ]);
    return paginated(rows.map(toScanDto), total, query);
  }

  async get(id: string): Promise<ScanModel> {
    const scan = await this.prisma.scan.findUnique({ where: { id } });
    if (!scan) throw new NotFoundException(`Scan ${id} not found`);
    return scan;
  }

  async activeScanIds(originalDomainId: string): Promise<string[]> {
    const rows = await this.prisma.scan.findMany({
      where: { originalDomainId, status: { in: ACTIVE_SCAN_STATUSES } },
      select: { id: true },
    });
    return rows.map((r) => r.id);
  }

  async cancel(id: string): Promise<ScanModel> {
    const scan = await this.get(id);
    const updated = await this.transition(
      id,
      ACTIVE_SCAN_STATUSES,
      ScanStatus.CANCELLED,
      {
        finishedAt: new Date(),
      },
    );
    if (!updated)
      throw new ConflictException(
        `Scan ${id} is already ${scan.status.toLowerCase()}`,
      );
    return updated;
  }

  /** Orchestrator: QUEUED → FUZZING. */
  startFuzzing(id: string) {
    return this.transition(id, [ScanStatus.QUEUED], ScanStatus.FUZZING, {
      startedAt: new Date(),
    });
  }

  /** Orchestrator: FUZZING → RESOLVING once permutations are known. */
  startResolving(id: string, permutationsTotal: number) {
    return this.transition(id, [ScanStatus.FUZZING], ScanStatus.RESOLVING, {
      permutationsTotal,
    });
  }

  complete(
    id: string,
    counts: Omit<ScanCounts, 'permutationsTotal' | 'resolvedCount'>,
  ) {
    return this.transition(
      id,
      [ScanStatus.FUZZING, ScanStatus.RESOLVING],
      ScanStatus.COMPLETED,
      {
        ...counts,
        finishedAt: new Date(),
      },
    );
  }

  fail(id: string, errorMessage: string) {
    return this.transition(id, ACTIVE_SCAN_STATUSES, ScanStatus.FAILED, {
      errorMessage: errorMessage.slice(0, 2_000),
      finishedAt: new Date(),
    });
  }

  /** Atomic counter increment after each DNS batch. */
  async recordProgress(id: string, resolved: number): Promise<void> {
    await this.bus.write({
      before: new ScanBeforeProgressEvent(id, resolved),
      work: async (tx, after) => {
        const scan = await tx.scan.update({
          where: { id },
          data: { resolvedCount: { increment: resolved } },
          select: { id: true, resolvedCount: true, permutationsTotal: true },
        });
        after.add(
          new ScanProgressEvent(
            scan.id,
            scan.resolvedCount,
            scan.permutationsTotal,
          ),
        );
      },
    });
  }

  /**
   * Compare-and-set status change. Returns null when the scan is not in one of `from`
   * (e.g. cancelled meanwhile) — callers treat that as "someone else already moved it".
   */
  private async transition(
    id: string,
    from: ScanStatus[],
    to: ScanStatus,
    data: Prisma.ScanUpdateManyMutationInput = {},
  ): Promise<ScanModel | null> {
    return this.bus.write({
      before: new ScanBeforeStatusChangeEvent(id, to),
      work: async (tx, after) => {
        const current = await tx.scan.findUnique({
          where: { id },
          select: { status: true },
        });
        if (!current) throw new NotFoundException(`Scan ${id} not found`);
        const { count } = await tx.scan.updateMany({
          where: { id, status: { in: from } },
          data: { ...data, status: to },
        });
        if (count === 0) return null;
        const scan = await tx.scan.findUniqueOrThrow({ where: { id } });
        after.add(
          new ScanStatusChangedEvent(
            id,
            scan.originalDomainId,
            current.status,
            to,
          ),
        );
        const name = FINISHED_EVENT[to];
        if (name) {
          after.add(
            new ScanFinishedEvent(
              name,
              id,
              scan.originalDomainId,
              isFullScan(scan.options),
              {
                permutationsTotal: scan.permutationsTotal,
                resolvedCount: scan.resolvedCount,
                registeredCount: scan.registeredCount,
                newCount: scan.newCount,
                failedCount: scan.failedCount,
              },
              scan.errorMessage ?? undefined,
            ),
          );
        }
        return scan;
      },
    });
  }

  private replay(
    existing: ScanModel,
    originalDomainId: string,
  ): CreateScanResult {
    if (existing.originalDomainId !== originalDomainId) {
      throw new ConflictException(
        'This Idempotency-Key was already used for a different original domain',
      );
    }
    return { scan: existing, created: false };
  }
}
