import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { TransactionalEventBus } from '../../common/events/transactional-event-bus.js';
import type { Prisma } from '../../database/generated/prisma/client.js';
import { PrismaService } from '../../database/prisma.service.js';
import type {
  RuleConfigDto,
  ScoringConfigDto,
  ScoringThresholdsDto,
  UpdateRuleConfigDto,
} from './dto/rule-config.dto.js';
import {
  RuleConfigBeforeUpdateEvent,
  RuleConfigUpdatedEvent,
  ScoringThresholdsBeforeUpdateEvent,
  ScoringThresholdsUpdatedEvent,
} from './events/rule-config.events.js';
import { toRuleConfigRecord } from './rule-engine.service.js';

/** Admin API over rule_configs / scoring_thresholds. Writes invalidate the scoring cache via events. */
@Injectable()
export class RuleConfigsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: TransactionalEventBus,
  ) {}

  async get(): Promise<ScoringConfigDto> {
    const [rows, t] = await Promise.all([
      this.prisma.ruleConfig.findMany({ orderBy: { key: 'asc' } }),
      this.prisma.scoringThreshold.findUniqueOrThrow({
        where: { key: 'global_score' },
      }),
    ]);
    return {
      rules: rows.map(toRuleConfigRecord),
      thresholds: {
        thresholdMediumRisk: t.thresholdMediumRisk,
        thresholdLowRisk: t.thresholdLowRisk,
      },
    };
  }

  async update(
    key: string,
    dto: UpdateRuleConfigDto,
    actor: string,
  ): Promise<RuleConfigDto> {
    if (dto.points && !dto.points.some((t) => t.condition === 'default')) {
      throw new BadRequestException('points must include a "default" tier');
    }
    const row = await this.bus.write({
      before: new RuleConfigBeforeUpdateEvent(
        key,
        dto as Record<string, unknown>,
      ),
      work: async (tx, after) => {
        const existing = await tx.ruleConfig.findUnique({ where: { key } });
        if (!existing) throw new NotFoundException(`Rule ${key} not found`);
        const saved = await tx.ruleConfig.update({
          where: { key },
          data: {
            enabled: dto.enabled,
            points: dto.points as unknown as Prisma.InputJsonValue | undefined,
            params: dto.params as Prisma.InputJsonValue | undefined,
          },
        });
        after.add(new RuleConfigUpdatedEvent(key, actor));
        return saved;
      },
    });
    return toRuleConfigRecord(row);
  }

  async updateThresholds(
    dto: ScoringThresholdsDto,
    actor: string,
  ): Promise<ScoringThresholdsDto> {
    if (dto.thresholdLowRisk >= dto.thresholdMediumRisk) {
      throw new BadRequestException(
        'thresholdLowRisk must be lower than thresholdMediumRisk',
      );
    }
    return this.bus.write({
      before: new ScoringThresholdsBeforeUpdateEvent(
        dto as unknown as Record<string, unknown>,
      ),
      work: async (tx, after) => {
        const saved = await tx.scoringThreshold.update({
          where: { key: 'global_score' },
          data: dto,
        });
        after.add(new ScoringThresholdsUpdatedEvent(actor));
        return {
          thresholdMediumRisk: saved.thresholdMediumRisk,
          thresholdLowRisk: saved.thresholdLowRisk,
        };
      },
    });
  }
}
