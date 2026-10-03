import { Injectable, NotFoundException } from '@nestjs/common';
import { TransactionalEventBus } from '../../common/events/transactional-event-bus.js';
import type { Prisma } from '../../database/generated/prisma/client.js';
import { PrismaService } from '../../database/prisma.service.js';
import type {
  AlertSubscriptionDto,
  CreateAlertSubscriptionDto,
  UpdateAlertSubscriptionDto,
} from './dto/alert.dto.js';
import {
  AlertSubscriptionBeforeWriteEvent,
  AlertSubscriptionWrittenEvent,
} from './events/alert.events.js';

const INCLUDE = {
  channel: { select: { name: true } },
  originalDomain: { select: { domain: true } },
} as const;
type Row = Prisma.AlertSubscriptionGetPayload<{ include: typeof INCLUDE }>;

const toDto = (s: Row): AlertSubscriptionDto => ({
  id: s.id,
  channelId: s.channelId,
  channelName: s.channel.name,
  originalDomainId: s.originalDomainId,
  brand: s.originalDomain?.domain ?? null,
  eventTypes: s.eventTypes,
  minRiskScore: s.minRiskScore,
  mode: s.mode,
  isActive: s.isActive,
  createdAt: s.createdAt,
});

@Injectable()
export class AlertSubscriptionsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: TransactionalEventBus,
  ) {}

  async list(channelId?: string): Promise<AlertSubscriptionDto[]> {
    const rows = await this.prisma.alertSubscription.findMany({
      where: channelId ? { channelId } : undefined,
      include: INCLUDE,
      orderBy: { createdAt: 'asc' },
    });
    return rows.map(toDto);
  }

  async create(
    dto: CreateAlertSubscriptionDto,
    actor: string,
  ): Promise<AlertSubscriptionDto> {
    const row = await this.bus.write({
      before: new AlertSubscriptionBeforeWriteEvent('create', null, actor),
      work: async (tx, after) => {
        const s = await tx.alertSubscription.create({
          data: {
            channelId: dto.channelId,
            originalDomainId: dto.originalDomainId ?? null,
            eventTypes: [...new Set(dto.eventTypes)],
            minRiskScore: dto.minRiskScore ?? 0,
            mode: dto.mode,
            isActive: dto.isActive ?? true,
          },
          include: INCLUDE,
        });
        after.add(new AlertSubscriptionWrittenEvent('create', s.id, actor));
        return s;
      },
    });
    return toDto(row);
  }

  async update(
    id: string,
    dto: UpdateAlertSubscriptionDto,
    actor: string,
  ): Promise<AlertSubscriptionDto> {
    await this.ensure(id);
    const row = await this.bus.write({
      before: new AlertSubscriptionBeforeWriteEvent('update', id, actor),
      work: async (tx, after) => {
        const s = await tx.alertSubscription.update({
          where: { id },
          data: {
            eventTypes: dto.eventTypes
              ? [...new Set(dto.eventTypes)]
              : undefined,
            minRiskScore: dto.minRiskScore,
            mode: dto.mode,
            isActive: dto.isActive,
          },
          include: INCLUDE,
        });
        after.add(new AlertSubscriptionWrittenEvent('update', id, actor));
        return s;
      },
    });
    return toDto(row);
  }

  async remove(id: string, actor: string): Promise<void> {
    await this.ensure(id);
    await this.bus.write({
      before: new AlertSubscriptionBeforeWriteEvent('delete', id, actor),
      work: async (tx, after) => {
        await tx.alertSubscription.delete({ where: { id } });
        after.add(new AlertSubscriptionWrittenEvent('delete', id, actor));
      },
    });
  }

  private async ensure(id: string): Promise<void> {
    if (
      !(await this.prisma.alertSubscription.findUnique({
        where: { id },
        select: { id: true },
      }))
    )
      throw new NotFoundException(`Alert subscription ${id} not found`);
  }
}
