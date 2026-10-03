import { ExpensiveThrottle } from '../../common/guards/api-key-throttler.guard.js';
import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import { ScannedDomainsQuery } from '../scanned-domains/scanned-domains.query.js';
import { QueuedJobDto } from '../whois-informations/dto/whois-information.dto.js';
import { AnalyticsEnqueuer } from './analytics.enqueuer.js';
import { AnalyticsQuery } from './analytics.query.js';
import {
  AnalyticsDto,
  SummaryDto,
  SummaryQueryDto,
  TrendPointDto,
  TrendsQueryDto,
} from './dto/analytics.dto.js';

@ApiTags('analytics')
@ApiSecurity('api-key')
@Controller()
export class AnalyticsController {
  constructor(
    private readonly query: AnalyticsQuery,
    private readonly scannedDomains: ScannedDomainsQuery,
    private readonly enqueuer: AnalyticsEnqueuer,
  ) {}

  @Get('scanned-domains/:id/analytics')
  @ApiOperation({
    summary: 'Scoring history for a look-alike, with the per-rule breakdown',
  })
  @ApiOkResponse({ type: [AnalyticsDto] })
  @ApiNotFoundResponse()
  async history(
    @Param('id', ParseUUIDPipe) id: string,
  ): Promise<AnalyticsDto[]> {
    await this.requireDomain(id);
    return this.query.history(id);
  }

  @ExpensiveThrottle()
  @Post('scanned-domains/:id/analytics/rescore')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Re-run all scoring rules now (e.g. after changing rule configs)',
  })
  @ApiAcceptedResponse({ type: QueuedJobDto })
  async rescore(@Param('id', ParseUUIDPipe) id: string): Promise<QueuedJobDto> {
    await this.requireDomain(id);
    return { queued: true, jobId: await this.enqueuer.enqueue(id, 'manual') };
  }

  @Get('analytics/summary')
  @ApiOperation({
    summary: 'Look-alike counts by threat level, status and technique',
  })
  @ApiOkResponse({ type: SummaryDto })
  summary(@Query() q: SummaryQueryDto): Promise<SummaryDto> {
    return this.query.summary(q.originalDomainId);
  }

  @Get('analytics/trends')
  @ApiOperation({
    summary: 'Daily new look-alikes and high-risk detections (UTC)',
  })
  @ApiOkResponse({ type: [TrendPointDto] })
  trends(@Query() q: TrendsQueryDto): Promise<TrendPointDto[]> {
    return this.query.trends(q.days, q.originalDomainId);
  }

  private async requireDomain(id: string) {
    if (!(await this.scannedDomains.getForEnrichment(id)))
      throw new NotFoundException(`Scanned domain ${id} not found`);
  }
}
