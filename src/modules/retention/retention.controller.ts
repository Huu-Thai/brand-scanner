import { ExpensiveThrottle } from '../../common/guards/api-key-throttler.guard.js';
import { InjectQueue } from '@nestjs/bullmq';
import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiProperty,
  ApiPropertyOptional,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import { IsIn, IsOptional } from 'class-validator';
import type { Queue } from 'bullmq';
import { RequireScope } from '../../common/decorators/auth.decorators.js';
import { Principal } from '../../common/decorators/principal.decorator.js';
import type { ApiPrincipal } from '../../common/guards/api-key.guard.js';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../config/configuration.js';
import { JOBS, type RetentionJobData } from '../../queue/jobs.js';
import { QUEUES } from '../../queue/queue.constants.js';
import { QueuedJobDto } from '../whois-informations/dto/whois-information.dto.js';
import {
  enqueueManual,
  RETENTION_SCHEDULER,
  SWEEP_SCHEDULER,
} from './retention.scheduler.js';
import { RetentionService } from './retention.service.js';

export class RunRetentionDto {
  @ApiPropertyOptional({
    enum: ['retention', 'orphan-sweep'],
    default: 'retention',
  })
  @IsOptional()
  @IsIn(['retention', 'orphan-sweep'])
  task?: 'retention' | 'orphan-sweep';
}

export class RetentionStatusDto {
  @ApiProperty({
    example: {
      days: 31,
      keepLatest: true,
      cron: '30 3 * * *',
      sweepCron: '0 4 * * 0',
    },
  })
  settings: Record<string, unknown>;
  @ApiPropertyOptional({
    nullable: true,
    description: 'Report of the last retention run',
  })
  lastRun: unknown;
  @ApiPropertyOptional({
    nullable: true,
    description: 'Report of the last orphan sweep',
  })
  lastSweep: unknown;
  @ApiPropertyOptional({ nullable: true }) nextRun: string | null;
  @ApiPropertyOptional({ nullable: true }) nextSweep: string | null;
}

@ApiTags('admin')
@ApiSecurity('api-key')
@RequireScope('admin')
@Controller('admin/retention')
export class RetentionController {
  constructor(
    private readonly retention: RetentionService,
    private readonly config: ConfigService<AppConfig, true>,
    @InjectQueue(QUEUES.RETENTION)
    private readonly queue: Queue<RetentionJobData>,
  ) {}

  @Get()
  @ApiOperation({
    summary:
      'Retention settings, last run / sweep reports and next scheduled runs (admin)',
  })
  @ApiOkResponse({ type: RetentionStatusDto })
  async status(): Promise<RetentionStatusDto> {
    const next = async (key: string) => {
      const s = await this.queue.getJobScheduler(key).catch(() => undefined);
      return s?.next ? new Date(s.next).toISOString() : null;
    };
    const { days, keepLatest, cron, sweepCron, batchSize } = this.config.get(
      'retention',
      { infer: true },
    );
    return {
      settings: { days, keepLatest, cron, sweepCron, batchSize },
      lastRun: await this.retention.lastRun(),
      lastSweep: await this.retention.lastSweep(),
      nextRun: await next(RETENTION_SCHEDULER),
      nextSweep: await next(SWEEP_SCHEDULER),
    };
  }

  @ExpensiveThrottle()
  @Post('run')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Queue a retention run (or orphan sweep) now (admin)',
  })
  @ApiAcceptedResponse({ type: QueuedJobDto })
  async run(
    @Body() dto: RunRetentionDto,
    @Principal() p: ApiPrincipal,
  ): Promise<QueuedJobDto> {
    const name =
      dto.task === 'orphan-sweep' ? JOBS.ORPHAN_SWEEP : JOBS.RETENTION_RUN;
    return {
      queued: true,
      jobId: await enqueueManual(this.queue, name, p.actor),
    };
  }
}
