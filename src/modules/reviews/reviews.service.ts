import { Injectable, NotFoundException } from '@nestjs/common';
import { type Paginated, paginated } from '../../common/dto/pagination.dto.js';
import { TransactionalEventBus } from '../../common/events/transactional-event-bus.js';
import type { Prisma } from '../../database/generated/prisma/client.js';
import { PrismaService } from '../../database/prisma.service.js';
import type {
  CreateReviewDto,
  ListReviewsQueryDto,
  ReviewDto,
} from './dto/review.dto.js';
import {
  ReviewBeforeCreateEvent,
  ReviewCreatedEvent,
} from './events/review.events.js';
import { VERDICT_STATUS } from './verdicts.js';

type ReviewRow = Prisma.ReviewGetPayload<{
  include: { scannedDomain: { select: { domain: true } } };
}>;

const toDto = (
  r:
    | ReviewRow
    | (Omit<ReviewRow, 'scannedDomain'> & {
        scannedDomain?: { domain: string };
      }),
): ReviewDto => ({
  id: r.id,
  scannedDomainId: r.scannedDomainId,
  domain: r.scannedDomain?.domain,
  verdict: r.verdict,
  notes: r.notes,
  reviewer: r.reviewer,
  previousStatus: r.previousStatus,
  newStatus: r.newStatus,
  createdAt: r.createdAt,
});

/** Analyst decisions (append-only audit trail; kept beyond retention). */
@Injectable()
export class ReviewsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: TransactionalEventBus,
  ) {}

  async create(
    scannedDomainId: string,
    dto: CreateReviewDto,
    reviewer: string,
  ): Promise<ReviewDto> {
    const row = await this.bus.write({
      before: new ReviewBeforeCreateEvent(
        scannedDomainId,
        dto.verdict,
        reviewer,
      ),
      work: async (tx, after) => {
        const sd = await tx.scannedDomain.findFirst({
          where: { id: scannedDomainId, deletedAt: null },
          select: { status: true, domain: true },
        });
        if (!sd)
          throw new NotFoundException(
            `Scanned domain ${scannedDomainId} not found`,
          );
        const review = await tx.review.create({
          data: {
            scannedDomainId,
            verdict: dto.verdict,
            notes: dto.notes || null,
            reviewer,
            previousStatus: sd.status,
            newStatus: VERDICT_STATUS[dto.verdict],
          },
        });
        after.add(
          new ReviewCreatedEvent(
            review.id,
            scannedDomainId,
            review.verdict,
            review.previousStatus,
            review.newStatus,
            reviewer,
          ),
        );
        return { ...review, scannedDomain: { domain: sd.domain } };
      },
    });
    return toDto(row);
  }

  async forDomain(scannedDomainId: string): Promise<ReviewDto[]> {
    const rows = await this.prisma.review.findMany({
      where: { scannedDomainId },
      orderBy: { createdAt: 'desc' },
      include: { scannedDomain: { select: { domain: true } } },
    });
    return rows.map(toDto);
  }

  async findAll(q: ListReviewsQueryDto): Promise<Paginated<ReviewDto>> {
    const where: Prisma.ReviewWhereInput = {
      verdict: q.verdict?.length ? { in: q.verdict } : undefined,
      reviewer: q.reviewer?.toLowerCase(),
      scannedDomain: {
        deletedAt: null,
        ...(q.originalDomainId ? { originalDomainId: q.originalDomainId } : {}),
      },
    };
    const [rows, total] = await Promise.all([
      this.prisma.review.findMany({
        where,
        orderBy: { createdAt: q.order },
        skip: q.skip,
        take: q.limit,
        include: { scannedDomain: { select: { domain: true } } },
      }),
      this.prisma.review.count({ where }),
    ]);
    return paginated(rows.map(toDto), total, q);
  }
}
