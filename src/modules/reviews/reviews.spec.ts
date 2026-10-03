import { NotFoundException } from '@nestjs/common';
import {
  DomainStatus,
  ReviewVerdict,
} from '../../database/generated/prisma/enums.js';
import { fakeBus } from '../../testing/fake-bus.js';
import { ReviewCreatedEvent, REVIEW_EVENTS } from './events/review.events.js';
import { ScanPipelineListener } from '../scanned-domains/listeners/scan-pipeline.listener.js';
import { ReviewsController } from './reviews.controller.js';
import { ReviewsService } from './reviews.service.js';
import { VERDICT_STATUS } from './verdicts.js';

const created = new Date('2026-10-01T10:00:00Z');

function setup(current: { status: DomainStatus; domain: string } | null) {
  const tx = {
    scannedDomain: { findFirst: vi.fn(async () => current) },
    review: {
      create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({
        id: 'r1',
        createdAt: created,
        ...data,
      })),
    },
  };
  const bus = fakeBus(tx);
  const prisma = {
    review: {
      findMany: vi.fn(async (_args: unknown) => []),
      count: vi.fn(async () => 0),
    },
  };
  return { svc: new ReviewsService(prisma as never, bus.bus), bus, tx, prisma };
}

describe('verdict → status', () => {
  it('maps every verdict', () => {
    expect(VERDICT_STATUS).toEqual({
      MALICIOUS: 'CONFIRMED_THREAT',
      SUSPICIOUS: 'UNDER_REVIEW',
      NEEDS_INFO: 'UNDER_REVIEW',
      BENIGN: 'ACTIVE',
      FALSE_POSITIVE: 'FALSE_POSITIVE',
    });
    expect(Object.keys(VERDICT_STATUS).sort()).toEqual(
      Object.values(ReviewVerdict).sort(),
    );
  });
});

describe('ReviewsService', () => {
  it('records the verdict with before/after status and emits review.created post-commit', async () => {
    const { svc, bus, tx } = setup({
      status: DomainStatus.NEW,
      domain: 'apypal.com',
    });
    const dto = await svc.create(
      'sd1',
      { verdict: ReviewVerdict.MALICIOUS, notes: 'kit' },
      'ana@x',
    );

    expect(tx.review.create).toHaveBeenCalledWith({
      data: {
        scannedDomainId: 'sd1',
        verdict: 'MALICIOUS',
        notes: 'kit',
        reviewer: 'ana@x',
        previousStatus: 'NEW',
        newStatus: 'CONFIRMED_THREAT',
      },
    });
    expect(dto).toMatchObject({
      id: 'r1',
      domain: 'apypal.com',
      newStatus: 'CONFIRMED_THREAT',
    });
    expect(bus.beforeNames()).toEqual([REVIEW_EVENTS.BEFORE_CREATE]);
    expect(bus.after).toEqual([
      expect.objectContaining({
        name: REVIEW_EVENTS.CREATED,
        reviewId: 'r1',
        scannedDomainId: 'sd1',
        previousStatus: 'NEW',
        newStatus: 'CONFIRMED_THREAT',
        reviewer: 'ana@x',
      }),
    ]);
  });

  it('stores empty notes as null', async () => {
    const { svc, tx } = setup({ status: DomainStatus.NEW, domain: 'a.com' });
    await svc.create(
      'sd1',
      { verdict: ReviewVerdict.BENIGN, notes: '' },
      'ana',
    );
    expect(tx.review.create.mock.calls[0][0].data.notes).toBeNull();
  });

  it('404s for unknown or deleted look-alikes without emitting', async () => {
    const { svc, bus } = setup(null);
    await expect(
      svc.create('x', { verdict: ReviewVerdict.BENIGN }, 'ana'),
    ).rejects.toBeInstanceOf(NotFoundException);
    expect(bus.after).toEqual([]);
  });

  it('filters the audit trail', async () => {
    const { svc, prisma } = setup(null);
    await svc.findAll({
      page: 1,
      limit: 25,
      skip: 0,
      order: 'desc',
      verdict: [ReviewVerdict.MALICIOUS],
      reviewer: 'Ana@X',
      originalDomainId: 'o1',
    } as never);
    expect(prisma.review.findMany.mock.calls[0][0]).toMatchObject({
      where: {
        verdict: { in: ['MALICIOUS'] },
        reviewer: 'ana@x',
        scannedDomain: { deletedAt: null, originalDomainId: 'o1' },
      },
      orderBy: { createdAt: 'desc' },
    });
  });
});

describe('ReviewsController', () => {
  it('attributes the review to the acting user', async () => {
    const reviews = { create: vi.fn(async () => ({ id: 'r1' })) };
    const ctrl = new ReviewsController(reviews as never, {} as never);
    await ctrl.create(
      'sd1',
      { verdict: ReviewVerdict.MALICIOUS },
      { name: 'manage-feed', scope: 'write', actor: 'ana@x' },
    );
    expect(reviews.create).toHaveBeenCalledWith(
      'sd1',
      { verdict: 'MALICIOUS' },
      'ana@x',
    );
  });

  it('404s the history of an unknown look-alike', async () => {
    const ctrl = new ReviewsController(
      {} as never,
      { getForEnrichment: vi.fn(async () => null) } as never,
    );
    await expect(ctrl.forDomain('x')).rejects.toBeInstanceOf(NotFoundException);
  });
});

describe('ScanPipelineListener.onReviewed', () => {
  it('applies the verdict as an authoritative review status change', async () => {
    const service = {
      changeStatus: vi.fn(async () => ({ changed: 1, unchanged: 0 })),
    };
    await new ScanPipelineListener(service as never).onReviewed(
      new ReviewCreatedEvent(
        'r1',
        'sd1',
        'MALICIOUS',
        'NEW',
        'CONFIRMED_THREAT',
        'ana@x',
      ),
    );
    expect(service.changeStatus).toHaveBeenCalledWith(
      ['sd1'],
      'CONFIRMED_THREAT',
      { source: 'review', actor: 'ana@x' },
    );
  });
});
