import { randomBytes } from 'node:crypto';
import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { isEmail } from 'class-validator';
import { TransactionalEventBus } from '../../common/events/transactional-event-bus.js';
import type { AlertChannel } from '../../database/generated/prisma/client.js';
import { AlertChannelType } from '../../database/generated/prisma/enums.js';
import { PrismaService } from '../../database/prisma.service.js';
import { AlertCrypto } from './alert-crypto.js';
import { AlertTargetGuard, UnsafeTargetError } from './alert-target.guard.js';
import { maskTarget } from './alert.types.js';
import type {
  AlertChannelDto,
  AlertChannelWithSecretDto,
  CreateAlertChannelDto,
  UpdateAlertChannelDto,
} from './dto/alert.dto.js';
import {
  AlertChannelBeforeWriteEvent,
  AlertChannelWrittenEvent,
} from './events/alert.events.js';
import type { ResolvedChannel } from './senders/alert-sender.js';

export const toChannelDto = (c: AlertChannel): AlertChannelDto => ({
  id: c.id,
  name: c.name,
  type: c.type,
  targetHint: c.targetHint,
  isActive: c.isActive,
  signed: !!c.signingSecretEncrypted,
  createdBy: c.createdBy,
  createdAt: c.createdAt,
  updatedAt: c.updatedAt,
});

const newSigningSecret = () => `whsec_${randomBytes(32).toString('base64url')}`;

@Injectable()
export class AlertChannelsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: TransactionalEventBus,
    private readonly crypto: AlertCrypto,
    private readonly guard: AlertTargetGuard,
  ) {}

  /** Normalises and validates a target for its channel type; throws 400 with a clear reason. */
  async validateTarget(
    type: AlertChannelType,
    target: string,
  ): Promise<string> {
    if (type === AlertChannelType.EMAIL) {
      const list = [
        ...new Set(
          target
            .split(',')
            .map((e) => e.trim().toLowerCase())
            .filter(Boolean),
        ),
      ];
      if (!list.length || list.length > 20 || !list.every((e) => isEmail(e)))
        throw new BadRequestException(
          'target must be 1–20 comma-separated e-mail addresses',
        );
      return list.join(', ');
    }
    try {
      const url = await this.guard.assertSafeUrl(target);
      if (type === AlertChannelType.SLACK && url.hostname !== 'hooks.slack.com')
        throw new BadRequestException(
          'Slack targets must be https://hooks.slack.com/… incoming-webhook URLs',
        );
      return url.toString();
    } catch (e) {
      if (e instanceof UnsafeTargetError)
        throw new BadRequestException(e.message);
      throw e;
    }
  }

  async create(
    dto: CreateAlertChannelDto,
    actor: string,
  ): Promise<AlertChannelWithSecretDto> {
    const target = await this.validateTarget(dto.type, dto.target);
    const secret =
      dto.type === AlertChannelType.WEBHOOK ? newSigningSecret() : undefined;
    const row = await this.bus.write({
      before: new AlertChannelBeforeWriteEvent('create', null, actor),
      work: async (tx, after) => {
        const c = await tx.alertChannel.create({
          data: {
            name: dto.name,
            type: dto.type,
            targetEncrypted: this.crypto.seal(target),
            targetHint: maskTarget(dto.type, target),
            signingSecretEncrypted: secret ? this.crypto.seal(secret) : null,
            isActive: dto.isActive ?? true,
            createdBy: actor,
          },
        });
        after.add(new AlertChannelWrittenEvent('create', c.id, actor));
        return c;
      },
    });
    return {
      ...toChannelDto(row),
      ...(secret ? { signingSecret: secret } : {}),
    };
  }

  async list(): Promise<AlertChannelDto[]> {
    return (
      await this.prisma.alertChannel.findMany({ orderBy: { name: 'asc' } })
    ).map(toChannelDto);
  }

  private async get(id: string): Promise<AlertChannel> {
    const c = await this.prisma.alertChannel.findUnique({ where: { id } });
    if (!c) throw new NotFoundException(`Alert channel ${id} not found`);
    return c;
  }

  async findOne(id: string): Promise<AlertChannelDto> {
    return toChannelDto(await this.get(id));
  }

  async update(
    id: string,
    dto: UpdateAlertChannelDto,
    actor: string,
  ): Promise<AlertChannelDto> {
    const current = await this.get(id);
    const target = dto.target
      ? await this.validateTarget(current.type, dto.target)
      : undefined;
    const row = await this.bus.write({
      before: new AlertChannelBeforeWriteEvent('update', id, actor),
      work: async (tx, after) => {
        const c = await tx.alertChannel.update({
          where: { id },
          data: {
            name: dto.name,
            isActive: dto.isActive,
            ...(target
              ? {
                  targetEncrypted: this.crypto.seal(target),
                  targetHint: maskTarget(current.type, target),
                }
              : {}),
          },
        });
        after.add(new AlertChannelWrittenEvent('update', id, actor));
        return c;
      },
    });
    return toChannelDto(row);
  }

  async rotateSecret(
    id: string,
    actor: string,
  ): Promise<AlertChannelWithSecretDto> {
    const current = await this.get(id);
    if (current.type !== AlertChannelType.WEBHOOK)
      throw new BadRequestException(
        'Only webhook channels have a signing secret',
      );
    const secret = newSigningSecret();
    const row = await this.bus.write({
      before: new AlertChannelBeforeWriteEvent('update', id, actor),
      work: async (tx, after) => {
        const c = await tx.alertChannel.update({
          where: { id },
          data: { signingSecretEncrypted: this.crypto.seal(secret) },
        });
        after.add(new AlertChannelWrittenEvent('update', id, actor));
        return c;
      },
    });
    return { ...toChannelDto(row), signingSecret: secret };
  }

  async remove(id: string, actor: string): Promise<void> {
    await this.get(id);
    await this.bus.write({
      before: new AlertChannelBeforeWriteEvent('delete', id, actor),
      work: async (tx, after) => {
        await tx.alertChannel.delete({ where: { id } }); // subscriptions + deliveries cascade
        after.add(new AlertChannelWrittenEvent('delete', id, actor));
      },
    });
  }

  /** Decrypted channel for sending (worker / test endpoint only — never serialised). */
  async resolve(id: string): Promise<ResolvedChannel & { isActive: boolean }> {
    const c = await this.get(id);
    return {
      id: c.id,
      name: c.name,
      type: c.type,
      isActive: c.isActive,
      target: this.crypto.open(c.targetEncrypted),
      signingSecret: c.signingSecretEncrypted
        ? this.crypto.open(c.signingSecretEncrypted)
        : null,
    };
  }
}
