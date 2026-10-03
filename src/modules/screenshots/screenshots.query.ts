import { Injectable, NotFoundException } from '@nestjs/common';
import type { ScreenshotModel } from '../../database/generated/prisma/models.js';
import { PrismaService } from '../../database/prisma.service.js';

@Injectable()
export class ScreenshotsQuery {
  constructor(private readonly prisma: PrismaService) {}

  forDomain(scannedDomainId: string, limit = 20): Promise<ScreenshotModel[]> {
    return this.prisma.screenshot.findMany({
      where: { scannedDomainId },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
  }

  async get(id: string): Promise<ScreenshotModel> {
    const row = await this.prisma.screenshot.findUnique({ where: { id } });
    if (!row) throw new NotFoundException(`Screenshot ${id} not found`);
    return row;
  }

  /** Newest successful capture of a look-alike (for scoring). */
  latestCaptured(scannedDomainId: string) {
    return this.prisma.screenshot.findFirst({
      where: { scannedDomainId, status: 'CAPTURED' },
      orderBy: { createdAt: 'desc' },
      select: {
        perceptualHash: true,
        faviconHash: true,
        pageSignals: true,
        pageTitle: true,
      },
    });
  }

  /** Look-alikes of a brand that have a capture — rescored when the brand reference changes. */
  async capturedLookalikes(originalDomainId: string): Promise<string[]> {
    const rows = await this.prisma.scannedDomain.findMany({
      where: {
        originalDomainId,
        deletedAt: null,
        screenshots: { some: { status: 'CAPTURED' } },
      },
      select: { id: true },
    });
    return rows.map((r) => r.id);
  }

  reference(originalDomainId: string) {
    return this.prisma.brandReference.findUnique({
      where: { originalDomainId },
    });
  }
}
