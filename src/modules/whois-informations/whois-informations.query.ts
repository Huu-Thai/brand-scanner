import { Injectable, NotFoundException } from '@nestjs/common';
import type { WhoisInformationModel } from '../../database/generated/prisma/models.js';
import { PrismaService } from '../../database/prisma.service.js';

/** Read-only access (safe to inject from other modules). */
@Injectable()
export class WhoisInformationsQuery {
  constructor(private readonly prisma: PrismaService) {}

  latest(scannedDomainId: string): Promise<WhoisInformationModel | null> {
    return this.prisma.whoisInformation.findFirst({
      where: { scannedDomainId },
      orderBy: { fetchedAt: 'desc' },
    });
  }

  /** True when no snapshot exists or the newest is older than `days`. */
  async isStale(scannedDomainId: string, days: number): Promise<boolean> {
    const latest = await this.prisma.whoisInformation.findFirst({
      where: { scannedDomainId },
      orderBy: { fetchedAt: 'desc' },
      select: { fetchedAt: true },
    });
    return (
      !latest || Date.now() - latest.fetchedAt.getTime() > days * 86_400_000
    );
  }

  history(
    scannedDomainId: string,
    limit = 20,
  ): Promise<WhoisInformationModel[]> {
    return this.prisma.whoisInformation.findMany({
      where: { scannedDomainId },
      orderBy: { fetchedAt: 'desc' },
      take: limit,
    });
  }

  async get(id: string): Promise<WhoisInformationModel> {
    const row = await this.prisma.whoisInformation.findUnique({
      where: { id },
    });
    if (!row) throw new NotFoundException(`WHOIS record ${id} not found`);
    return row;
  }
}
