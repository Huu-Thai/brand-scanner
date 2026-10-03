import {
  Controller,
  Get,
  Headers,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiExcludeController } from '@nestjs/swagger';
import type { Response } from 'express';
import { timingSafeEqual } from 'node:crypto';
import { Public } from '../common/decorators/auth.decorators.js';
import type { AppConfig } from '../config/configuration.js';
import { MetricsCollector } from './metrics.collector.js';

/** Prometheus scrape endpoint: GET /api/v1/metrics (bearer METRICS_TOKEN when configured). */
@ApiExcludeController()
@Public()
@Controller('metrics')
export class MetricsController {
  constructor(
    private readonly collector: MetricsCollector,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  @Get()
  async scrape(
    @Headers('authorization') auth: string | undefined,
    @Res() res: Response,
  ): Promise<void> {
    if (!authorized(this.config.get('metrics', { infer: true }).token, auth)) {
      throw new UnauthorizedException('Metrics token required');
    }
    const { contentType, body } = await this.collector.scrape();
    res.setHeader('content-type', contentType);
    res.setHeader('cache-control', 'no-store');
    res.send(body);
  }
}

export function authorized(
  token: string | undefined,
  header: string | undefined,
): boolean {
  if (!token) return true;
  const given = Buffer.from(header?.replace(/^Bearer\s+/i, '') ?? '');
  const want = Buffer.from(token);
  return given.length === want.length && timingSafeEqual(given, want);
}
