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
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { WhoisInformationModel } from '../../database/generated/prisma/models.js';
import { ScannedDomainsQuery } from '../scanned-domains/scanned-domains.query.js';
import {
  QueuedJobDto,
  WhoisInformationDto,
} from './dto/whois-information.dto.js';
import { WhoisEnqueuer } from './whois.enqueuer.js';
import { WhoisInformationsQuery } from './whois-informations.query.js';

export function toWhoisDto(
  row: WhoisInformationModel,
  includeRaw = false,
): WhoisInformationDto {
  return {
    id: row.id,
    scannedDomainId: row.scannedDomainId,
    source: row.source,
    registrar: row.registrar,
    registrantOrg: row.registrantOrg,
    registrantCountry: row.registrantCountry,
    abuseEmail: row.abuseEmail,
    emails: row.emails ?? [],
    nameServers: row.nameServers ?? [],
    statuses: row.statuses ?? [],
    dnssec: row.dnssec,
    whoisServer: row.whoisServer,
    createdDate: row.createdDate,
    updatedDate: row.updatedDate,
    expiresDate: row.expiresDate,
    domainAgeDays: row.createdDate
      ? Math.floor(
          (row.fetchedAt.getTime() - row.createdDate.getTime()) / 86_400_000,
        )
      : null,
    parseSucceeded: row.parseSucceeded,
    fetchedAt: row.fetchedAt,
    ...(includeRaw ? { rawText: row.rawText } : {}),
  };
}

@ApiTags('whois')
@ApiSecurity('api-key')
@Controller()
export class WhoisInformationsController {
  constructor(
    private readonly query: WhoisInformationsQuery,
    private readonly scannedDomains: ScannedDomainsQuery,
    private readonly enqueuer: WhoisEnqueuer,
  ) {}

  @Get('scanned-domains/:id/whois')
  @ApiOperation({
    summary: 'WHOIS/RDAP history for a look-alike (newest first)',
  })
  @ApiOkResponse({ type: [WhoisInformationDto] })
  async history(
    @Param('id', ParseUUIDPipe) id: string,
  ): Promise<WhoisInformationDto[]> {
    await this.requireDomain(id);
    return (await this.query.history(id)).map((r) => toWhoisDto(r));
  }

  @Get('whois-informations/:id')
  @ApiOperation({
    summary: 'One WHOIS/RDAP snapshot including the raw response',
  })
  @ApiOkResponse({ type: WhoisInformationDto })
  @ApiNotFoundResponse()
  async get(
    @Param('id', ParseUUIDPipe) id: string,
  ): Promise<WhoisInformationDto> {
    return toWhoisDto(await this.query.get(id), true);
  }

  @ExpensiveThrottle()
  @Post('scanned-domains/:id/whois/refresh')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary:
      'Re-fetch WHOIS now (ignores the refresh window); scoring re-runs afterwards',
  })
  @ApiAcceptedResponse({ type: QueuedJobDto })
  @ApiNotFoundResponse()
  async refresh(@Param('id', ParseUUIDPipe) id: string): Promise<QueuedJobDto> {
    const domain = await this.requireDomain(id);
    const jobId = await this.enqueuer.enqueue({
      scannedDomainId: id,
      domain: domain.domain,
      force: true,
    });
    return { queued: true, jobId };
  }

  private async requireDomain(id: string) {
    const domain = await this.scannedDomains.getForEnrichment(id);
    if (!domain) throw new NotFoundException(`Scanned domain ${id} not found`);
    return domain;
  }
}
