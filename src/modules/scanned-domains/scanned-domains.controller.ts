import { ExpensiveThrottle } from '../../common/guards/api-key-throttler.guard.js';
import {
  Body,
  Controller,
  Logger,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Query,
  Res,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiNoContentResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiProduces,
  ApiSecurity,
  ApiTags,
  ApiUnprocessableEntityResponse,
} from '@nestjs/swagger';
import type { Response } from 'express';
import { Principal } from '../../common/decorators/principal.decorator.js';
import type { ApiPrincipal } from '../../common/guards/api-key.guard.js';
import { QueuedJobDto } from '../whois-informations/dto/whois-information.dto.js';
import {
  BulkUpdateResultDto,
  BulkUpdateScannedDomainsDto,
  ExportScannedDomainsQueryDto,
  ListScannedDomainsQueryDto,
  ScannedDomainChangesDto,
  ScannedDomainDto,
  ScannedDomainPageDto,
} from './dto/scanned-domain.dto.js';
import { RescanEnqueuer } from './rescan.enqueuer.js';
import { ScannedDomainsExportService } from './scanned-domains.export.js';
import { ScannedDomainsQuery } from './scanned-domains.query.js';
import { ScannedDomainsReadService } from './scanned-domains.read.service.js';
import { ScannedDomainsService } from './scanned-domains.service.js';

@ApiTags('scanned-domains')
@ApiSecurity('api-key')
@Controller('scanned-domains')
export class ScannedDomainsController {
  private readonly logger = new Logger(ScannedDomainsController.name);

  constructor(
    private readonly read: ScannedDomainsReadService,
    private readonly service: ScannedDomainsService,
    private readonly query: ScannedDomainsQuery,
    private readonly exporter: ScannedDomainsExportService,
    private readonly rescans: RescanEnqueuer,
  ) {}

  @Get()
  @ApiOperation({
    summary:
      'List registered look-alikes (filter by original domain, scan, status, technique…)',
  })
  @ApiOkResponse({ type: ScannedDomainPageDto })
  findAll(@Query() query: ListScannedDomainsQueryDto) {
    return this.read.findAll(query);
  }

  @ExpensiveThrottle()
  @Get('export')
  @ApiOperation({
    summary:
      'Stream matching look-alikes as CSV, JSON or a STIX 2.1 bundle (same filters as the list)',
  })
  @ApiProduces('text/csv', 'application/json')
  async export(
    @Query() query: ExportScannedDomainsQueryDto,
    @Res() res: Response,
  ): Promise<void> {
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const ext = query.format === 'csv' ? 'csv' : 'json';
    res.setHeader('content-type', this.exporter.contentType(query.format));
    res.setHeader(
      'content-disposition',
      `attachment; filename="lookalikes-${stamp}${query.format === 'stix' ? '.stix' : ''}.${ext}"`,
    );
    res.setHeader('cache-control', 'no-store');
    try {
      for await (const chunk of this.exporter.stream(query, query.format)) {
        if (!res.write(chunk))
          await new Promise((resolve) => res.once('drain', resolve));
      }
      res.end();
    } catch (e) {
      // Headers are already sent: abort so the client sees a truncated download, not a "200".
      this.logger.error(`Export failed: ${(e as Error).message}`);
      res.destroy(e as Error);
    }
  }

  @ExpensiveThrottle()
  @Patch('bulk')
  @ApiOperation({
    summary:
      'Set status and/or tags on up to 500 look-alikes (each change is all-or-nothing)',
  })
  @ApiOkResponse({ type: BulkUpdateResultDto })
  @ApiUnprocessableEntityResponse({
    description:
      'A status transition is not allowed for one of the domains (nothing changed)',
  })
  bulk(
    @Body() dto: BulkUpdateScannedDomainsDto,
    @Principal() p: ApiPrincipal,
  ): Promise<BulkUpdateResultDto> {
    return this.apply(dto.ids, dto, p);
  }

  @Get(':id')
  @ApiOperation({
    summary:
      'Get one scanned domain (WHOIS, screenshots, scores and reviews are sub-resources)',
  })
  @ApiOkResponse({ type: ScannedDomainDto })
  @ApiNotFoundResponse()
  findOne(@Param('id', ParseUUIDPipe) id: string): Promise<ScannedDomainDto> {
    return this.read.findOne(id);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Change status and/or tags' })
  @ApiOkResponse({ type: ScannedDomainDto })
  @ApiNotFoundResponse()
  @ApiUnprocessableEntityResponse({
    description: 'Status transition not allowed',
  })
  async update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: ScannedDomainChangesDto,
    @Principal() p: ApiPrincipal,
  ): Promise<ScannedDomainDto> {
    await this.read.findOne(id);
    await this.apply([id], dto, p);
    return this.read.findOne(id);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Soft-delete (hidden everywhere; history kept until retention)',
  })
  @ApiNoContentResponse()
  @ApiNotFoundResponse()
  async remove(
    @Param('id', ParseUUIDPipe) id: string,
    @Principal() p: ApiPrincipal,
  ): Promise<void> {
    if (!(await this.service.softDelete(id, p.actor)))
      throw new NotFoundException(`Scanned domain ${id} not found`);
  }

  @ExpensiveThrottle()
  @Post(':id/rescan')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Re-resolve DNS now, then refresh WHOIS, screenshot and score',
  })
  @ApiAcceptedResponse({ type: QueuedJobDto })
  @ApiNotFoundResponse()
  async rescan(
    @Param('id', ParseUUIDPipe) id: string,
    @Principal() p: ApiPrincipal,
  ): Promise<QueuedJobDto> {
    const sd = await this.query.getForEnrichment(id);
    if (!sd) throw new NotFoundException(`Scanned domain ${id} not found`);
    return {
      queued: true,
      jobId: await this.rescans.enqueue({
        scannedDomainId: id,
        domain: sd.domain,
        actor: p.actor,
      }),
    };
  }

  private async apply(
    ids: string[],
    dto: ScannedDomainChangesDto,
    p: ApiPrincipal,
  ): Promise<BulkUpdateResultDto> {
    const statusChanged = dto.status
      ? (
          await this.service.changeStatus(ids, dto.status, {
            source: 'manual',
            actor: p.actor,
          })
        ).changed
      : 0;
    const tagsUpdated =
      dto.addTags?.length || dto.removeTags?.length
        ? await this.service.updateTags(
            ids,
            { add: dto.addTags, remove: dto.removeTags },
            p.actor,
          )
        : 0;
    return { statusChanged, tagsUpdated };
  }
}
