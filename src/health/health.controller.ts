import { Controller, Get } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { SkipThrottle } from '@nestjs/throttler';
import {
  HealthCheck,
  HealthCheckService,
  type HealthIndicatorFunction,
} from '@nestjs/terminus';
import { Public } from '../common/decorators/auth.decorators.js';
import type { AppConfig } from '../config/configuration.js';
import { HealthIndicators } from './health.indicators.js';

@ApiTags('health')
@Controller('health')
export class HealthController {
  constructor(
    private readonly health: HealthCheckService,
    private readonly indicators: HealthIndicators,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  @Get()
  @Public()
  @SkipThrottle()
  @HealthCheck()
  @ApiOperation({
    summary:
      'Readiness: database, authenticated Redis, object storage, Selenium Grid',
  })
  check() {
    const checks: HealthIndicatorFunction[] = [
      () => this.indicators.database(),
      () => this.indicators.redisPing(),
      () => this.indicators.objectStorage(),
    ];
    if (this.config.get('selenium', { infer: true }).healthCheck) {
      checks.push(() => this.indicators.selenium());
    }
    return this.health.check(checks);
  }

  @Get('live')
  @Public()
  @SkipThrottle()
  @ApiOperation({
    summary: 'Liveness: the process is up (no dependency checks)',
  })
  live() {
    return { status: 'ok' };
  }
}
