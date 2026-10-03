import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { type Paginated, paginated } from '../../common/dto/pagination.dto.js';
import { TransactionalEventBus } from '../../common/events/transactional-event-bus.js';
import {
  InvalidDomainError,
  normalizeDomain,
} from '../../common/utils/domain.js';
import type { Prisma } from '../../database/generated/prisma/client.js';
import { PrismaService } from '../../database/prisma.service.js';
import type {
  CreateOriginalDomainDto,
  ListOriginalDomainsQueryDto,
  OriginalDomainDetailDto,
  OriginalDomainDto,
  UpdateOriginalDomainDto,
} from './dto/original-domain.dto.js';
import {
  OriginalDomainBeforeCreateEvent,
  OriginalDomainBeforeDeleteEvent,
  OriginalDomainBeforeUpdateEvent,
  OriginalDomainCreatedEvent,
  OriginalDomainDeletedEvent,
  OriginalDomainUpdatedEvent,
} from './events/original-domain.events.js';
import { toOriginalDomainDto, toSnapshot } from './original-domains.mapper.js';

/** Write + API-facing reads for original domains. Every write goes through TransactionalEventBus. */
@Injectable()
export class OriginalDomainsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: TransactionalEventBus,
  ) {}

  async create(dto: CreateOriginalDomainDto): Promise<OriginalDomainDto> {
    const normalized = this.normalize(dto.domain);
    const row = await this.bus.write({
      before: new OriginalDomainBeforeCreateEvent(normalized.ascii),
      work: async (tx, after) => {
        const existing = await tx.originalDomain.findUnique({
          where: { domain: normalized.ascii },
        });
        if (existing && !existing.deletedAt) {
          throw new ConflictException(
            `${normalized.unicode} is already registered (id ${existing.id})`,
          );
        }
        const data = {
          unicodeDomain: normalized.unicode,
          label: dto.label ?? null,
          scanSchedule: dto.scanSchedule ?? null,
          scanOptions: (dto.scanOptions ?? {}) as Prisma.InputJsonValue,
          isActive: dto.isActive ?? true,
        };
        // A soft-deleted domain is restored in place, so its history and look-alikes return with it.
        const saved = existing
          ? await tx.originalDomain.update({
              where: { id: existing.id },
              data: { ...data, deletedAt: null },
            })
          : await tx.originalDomain.create({
              data: { domain: normalized.ascii, ...data },
            });
        after.add(
          new OriginalDomainCreatedEvent(toSnapshot(saved), Boolean(existing)),
        );
        return saved;
      },
    });
    return toOriginalDomainDto(row);
  }

  async findAll(
    query: ListOriginalDomainsQueryDto,
  ): Promise<Paginated<OriginalDomainDto>> {
    const where: Prisma.OriginalDomainWhereInput = {
      deletedAt: null,
      isActive: query.isActive,
      ...(query.search
        ? {
            OR: [
              { domain: { contains: query.search.toLowerCase() } },
              {
                unicodeDomain: { contains: query.search, mode: 'insensitive' },
              },
              { label: { contains: query.search, mode: 'insensitive' } },
            ],
          }
        : {}),
    };
    const [rows, total] = await Promise.all([
      this.prisma.originalDomain.findMany({
        where,
        orderBy: { createdAt: query.order },
        skip: query.skip,
        take: query.limit,
      }),
      this.prisma.originalDomain.count({ where }),
    ]);
    return paginated(rows.map(toOriginalDomainDto), total, query);
  }

  async findOne(id: string): Promise<OriginalDomainDetailDto> {
    const row = await this.prisma.originalDomain.findFirst({
      where: { id, deletedAt: null },
    });
    if (!row) throw new NotFoundException(`Original domain ${id} not found`);
    const [groups, latestScan] = await Promise.all([
      this.prisma.scannedDomain.groupBy({
        by: ['threatLevel'],
        where: { originalDomainId: id, deletedAt: null },
        _count: { _all: true },
      }),
      this.prisma.scan.findFirst({
        where: { originalDomainId: id },
        orderBy: { createdAt: 'desc' },
        select: { id: true, status: true, createdAt: true, finishedAt: true },
      }),
    ]);
    const byThreatLevel = Object.fromEntries(
      groups.map((g) => [g.threatLevel, g._count._all]),
    );
    return {
      ...toOriginalDomainDto(row),
      stats: {
        trackedDomains: groups.reduce((n, g) => n + g._count._all, 0),
        byThreatLevel,
        latestScan,
      },
    };
  }

  async update(
    id: string,
    dto: UpdateOriginalDomainDto,
  ): Promise<OriginalDomainDto> {
    const changes: Prisma.OriginalDomainUpdateInput = {
      label: dto.label,
      scanSchedule: dto.scanSchedule,
      isActive: dto.isActive,
      scanOptions: dto.scanOptions as Prisma.InputJsonValue | undefined,
    };
    const changedFields = Object.entries(changes)
      .filter(([, v]) => v !== undefined)
      .map(([k]) => k);
    const row = await this.bus.write({
      before: new OriginalDomainBeforeUpdateEvent(
        id,
        dto as Record<string, unknown>,
      ),
      work: async (tx, after) => {
        await this.requireActive(tx, id);
        const saved = await tx.originalDomain.update({
          where: { id },
          data: changes,
        });
        after.add(
          new OriginalDomainUpdatedEvent(toSnapshot(saved), changedFields),
        );
        return saved;
      },
    });
    return toOriginalDomainDto(row);
  }

  async remove(id: string): Promise<void> {
    await this.bus.write({
      before: new OriginalDomainBeforeDeleteEvent(id),
      work: async (tx, after) => {
        await this.requireActive(tx, id);
        const saved = await tx.originalDomain.update({
          where: { id },
          data: { deletedAt: new Date(), isActive: false },
        });
        after.add(new OriginalDomainDeletedEvent(toSnapshot(saved)));
      },
    });
  }

  /** Records a completed scan. Called from the scan.completed listener. */
  async markScanned(id: string, at: Date): Promise<void> {
    await this.bus.write({
      before: new OriginalDomainBeforeUpdateEvent(id, { lastScannedAt: at }),
      work: async (tx, after) => {
        const saved = await tx.originalDomain.update({
          where: { id },
          data: { lastScannedAt: at },
        });
        after.add(
          new OriginalDomainUpdatedEvent(toSnapshot(saved), ['lastScannedAt']),
        );
      },
    });
  }

  private async requireActive(tx: Prisma.TransactionClient, id: string) {
    const row = await tx.originalDomain.findFirst({
      where: { id, deletedAt: null },
      select: { id: true },
    });
    if (!row) throw new NotFoundException(`Original domain ${id} not found`);
  }

  private normalize(domain: string) {
    try {
      return normalizeDomain(domain);
    } catch (e) {
      if (e instanceof InvalidDomainError)
        throw new BadRequestException(e.message);
      throw e;
    }
  }
}
