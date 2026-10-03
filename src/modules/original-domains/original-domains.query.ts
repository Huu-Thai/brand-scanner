import {
  Injectable,
  NotFoundException,
  UnprocessableEntityException,
} from '@nestjs/common';
import type { OriginalDomainModel } from '../../database/generated/prisma/models.js';
import { PrismaService } from '../../database/prisma.service.js';

/** Read-only access for other modules (safe to inject cross-module — it never writes). */
@Injectable()
export class OriginalDomainsQuery {
  constructor(private readonly prisma: PrismaService) {}

  async getScannable(id: string): Promise<OriginalDomainModel> {
    const row = await this.prisma.originalDomain.findFirst({
      where: { id, deletedAt: null },
    });
    if (!row) throw new NotFoundException(`Original domain ${id} not found`);
    if (!row.isActive)
      throw new UnprocessableEntityException(
        `Original domain ${row.domain} is inactive`,
      );
    return row;
  }

  findByDomain(asciiDomain: string): Promise<OriginalDomainModel | null> {
    return this.prisma.originalDomain.findFirst({
      where: { domain: asciiDomain, deletedAt: null },
    });
  }

  findScheduled(): Promise<Pick<OriginalDomainModel, 'id' | 'scanSchedule'>[]> {
    return this.prisma.originalDomain.findMany({
      where: { deletedAt: null, isActive: true, scanSchedule: { not: null } },
      select: { id: true, scanSchedule: true },
    });
  }

  /** Active, non-deleted brands (CT monitoring matches certificates against these). */
  listActive(): Promise<{ id: string; domain: string }[]> {
    return this.prisma.originalDomain.findMany({
      where: { isActive: true, deletedAt: null },
      select: { id: true, domain: true },
    });
  }
}
