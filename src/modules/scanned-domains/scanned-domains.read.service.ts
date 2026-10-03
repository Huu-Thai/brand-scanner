import { Injectable, NotFoundException } from '@nestjs/common';
import { type Paginated, paginated } from '../../common/dto/pagination.dto.js';
import type { Prisma } from '../../database/generated/prisma/client.js';
import type { ScannedDomainModel } from '../../database/generated/prisma/models.js';
import { PrismaService } from '../../database/prisma.service.js';
import type {
  ListScannedDomainsQueryDto,
  ScannedDomainDto,
  ScannedDomainFilters,
} from './dto/scanned-domain.dto.js';

const WITH_BRAND = { originalDomain: { select: { domain: true } } } as const;

export function toScannedDomainDto(
  row: ScannedDomainModel & { originalDomain?: { domain: string } },
): ScannedDomainDto {
  return {
    id: row.id,
    originalDomainId: row.originalDomainId,
    lastScanId: row.lastScanId,
    domain: row.domain,
    unicodeDomain: row.unicodeDomain,
    fuzzer: row.fuzzer,
    dnsA: row.dnsA ?? [],
    dnsAaaa: row.dnsAaaa ?? [],
    dnsMx: row.dnsMx ?? [],
    dnsNs: row.dnsNs ?? [],
    dnsTtl: row.dnsTtl,
    dnsErrors: row.dnsErrors ?? [],
    status: row.status,
    riskScore: row.riskScore,
    threatLevel: row.threatLevel,
    tags: row.tags ?? [],
    firstSeenAt: row.firstSeenAt,
    lastSeenAt: row.lastSeenAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    originalDomain: row.originalDomain?.domain,
  };
}

/** Shared by list and export so both honour exactly the same filters. */
export function buildScannedDomainWhere(
  query: ScannedDomainFilters,
): Prisma.ScannedDomainWhereInput {
  return {
    deletedAt: null,
    originalDomainId: query.originalDomainId,
    lastScanId: query.scanId,
    status: query.status?.length ? { in: query.status } : undefined,
    threatLevel: query.threatLevel?.length
      ? { in: query.threatLevel }
      : undefined,
    fuzzer: query.fuzzer?.length ? { in: query.fuzzer } : undefined,
    riskScore:
      query.minScore !== undefined ? { gte: query.minScore } : undefined,
    ...(query.search
      ? {
          OR: [
            { domain: { contains: query.search.toLowerCase() } },
            { unicodeDomain: { contains: query.search, mode: 'insensitive' } },
          ],
        }
      : {}),
  };
}

/** Read API for scanned domains (writes live in ScannedDomainsService). */
@Injectable()
export class ScannedDomainsReadService {
  constructor(private readonly prisma: PrismaService) {}

  async findAll(
    query: ListScannedDomainsQueryDto,
  ): Promise<Paginated<ScannedDomainDto>> {
    const where = buildScannedDomainWhere(query);
    const [rows, total] = await Promise.all([
      this.prisma.scannedDomain.findMany({
        where,
        orderBy: [{ [query.sort]: query.order }, { id: 'asc' }],
        skip: query.skip,
        take: query.limit,
        include: WITH_BRAND,
      }),
      this.prisma.scannedDomain.count({ where }),
    ]);
    return paginated(rows.map(toScannedDomainDto), total, query);
  }

  async findOne(id: string): Promise<ScannedDomainDto> {
    const row = await this.prisma.scannedDomain.findFirst({
      where: { id, deletedAt: null },
      include: WITH_BRAND,
    });
    if (!row) throw new NotFoundException(`Scanned domain ${id} not found`);
    return toScannedDomainDto(row);
  }
}
