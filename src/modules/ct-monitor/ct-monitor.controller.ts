import { Controller, Get, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ApiOkResponse,
  ApiOperation,
  ApiProperty,
  ApiPropertyOptional,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { Redis } from 'ioredis';
import type { AppConfig } from '../../config/configuration.js';
import { REDIS_CLIENT } from '../../redis/redis.module.js';
import { CT_LEADER_KEY, CT_STATS_KEY } from './ct-stream.service.js';

export class CtMonitorStatusDto {
  @ApiProperty() enabled: boolean;
  @ApiProperty({ description: 'A process holds the stream lease' })
  leaderElected: boolean;
  @ApiProperty() connected: boolean;
  @ApiPropertyOptional({ nullable: true }) streamUrl: string | null;
  @ApiProperty({ description: 'Certificates received since stats were reset' })
  certificates: number;
  @ApiProperty({ description: 'Brand look-alike candidates queued' })
  matches: number;
  @ApiPropertyOptional({ nullable: true }) lastMessageAt: string | null;
  @ApiPropertyOptional({ nullable: true }) connectedSince: string | null;
}

@ApiTags('ct-monitor')
@ApiSecurity('api-key')
@Controller('ct-monitor')
export class CtMonitorController {
  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    @Inject(REDIS_CLIENT) private readonly redis: Redis,
  ) {}

  @Get('status')
  @ApiOperation({
    summary:
      'Certificate Transparency monitor: leader, connection and counters',
  })
  @ApiOkResponse({ type: CtMonitorStatusDto })
  async status(): Promise<CtMonitorStatusDto> {
    const { enabled, streamUrl } = this.config.get('ct', { infer: true });
    const [stats, leader] = await Promise.all([
      this.redis.hgetall(CT_STATS_KEY),
      this.redis.exists(CT_LEADER_KEY),
    ]);
    const fresh =
      stats.lastMessageAt &&
      Date.now() - Date.parse(stats.lastMessageAt) < 120_000;
    return {
      enabled,
      leaderElected: leader === 1,
      connected: enabled && leader === 1 && stats.connected === '1' && !!fresh,
      streamUrl: enabled ? streamUrl : null,
      certificates: Number(stats.certificates ?? 0),
      matches: Number(stats.matches ?? 0),
      lastMessageAt: stats.lastMessageAt || null,
      connectedSince: stats.connectedSince || null,
    };
  }
}
