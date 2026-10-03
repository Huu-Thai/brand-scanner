import { Injectable, UnprocessableEntityException } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { PrismaService } from '../../../database/prisma.service.js';
import {
  SCANNED_DOMAIN_EVENTS,
  type ScannedDomainBeforeStatusChangeEvent,
} from '../events/scanned-domain.events.js';
import { transitionError } from '../status-rules.js';

/**
 * Before-event veto: rejects the whole status change if any look-alike would make a
 * disallowed transition. Reads only; never writes (PLAN.md §4).
 */
@Injectable()
export class StatusRulesListener {
  constructor(private readonly prisma: PrismaService) {}

  @OnEvent(SCANNED_DOMAIN_EVENTS.BEFORE_STATUS_CHANGE, {
    async: true,
    promisify: true,
    suppressErrors: false,
  })
  async validate(event: ScannedDomainBeforeStatusChangeEvent): Promise<void> {
    const rows = await this.prisma.scannedDomain.findMany({
      where: { id: { in: event.scannedDomainIds }, deletedAt: null },
      select: { id: true, domain: true, status: true },
    });
    const violations = rows
      .map((r) => ({
        domain: r.domain,
        error: transitionError(r.status, event.to, event.source),
      }))
      .filter((v) => v.error !== null);
    if (violations.length) {
      throw new UnprocessableEntityException(
        violations.slice(0, 20).map((v) => `${v.domain}: ${v.error}`),
      );
    }
  }
}
