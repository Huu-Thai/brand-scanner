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
  Res,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiFoundResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { Response } from 'express';
import { API_PREFIX } from '../../common/constants/api.constants.js';
import type { ScreenshotModel } from '../../database/generated/prisma/models.js';
import { StorageService } from '../../storage/storage.service.js';
import { ScannedDomainsQuery } from '../scanned-domains/scanned-domains.query.js';
import { QueuedJobDto } from '../whois-informations/dto/whois-information.dto.js';
import { ScreenshotDto } from './dto/screenshot.dto.js';
import { ScreenshotEnqueuer } from './screenshot.enqueuer.js';
import { ScreenshotsQuery } from './screenshots.query.js';

export function toScreenshotDto(row: ScreenshotModel): ScreenshotDto {
  return {
    id: row.id,
    scannedDomainId: row.scannedDomainId,
    scanId: row.scanId,
    status: row.status,
    requestedUrl: row.requestedUrl,
    finalUrl: row.finalUrl,
    httpStatus: row.httpStatus,
    pageTitle: row.pageTitle,
    width: row.width,
    height: row.height,
    sizeBytes: row.sizeBytes,
    perceptualHash: row.perceptualHash,
    errorMessage: row.errorMessage,
    imageUrl: row.storageKey
      ? `/${API_PREFIX}/screenshots/${row.id}/image`
      : null,
    capturedAt: row.capturedAt,
    createdAt: row.createdAt,
  };
}

@ApiTags('screenshots')
@ApiSecurity('api-key')
@Controller()
export class ScreenshotsController {
  constructor(
    private readonly query: ScreenshotsQuery,
    private readonly scannedDomains: ScannedDomainsQuery,
    private readonly storage: StorageService,
    private readonly enqueuer: ScreenshotEnqueuer,
  ) {}

  @Get('scanned-domains/:id/screenshots')
  @ApiOperation({ summary: 'Captures of a look-alike (newest first)' })
  @ApiOkResponse({ type: [ScreenshotDto] })
  async list(@Param('id', ParseUUIDPipe) id: string): Promise<ScreenshotDto[]> {
    await this.requireDomain(id);
    return (await this.query.forDomain(id)).map(toScreenshotDto);
  }

  @ExpensiveThrottle()
  @Post('scanned-domains/:id/screenshots')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Capture the look-alike again now' })
  @ApiAcceptedResponse({ type: QueuedJobDto })
  async recapture(
    @Param('id', ParseUUIDPipe) id: string,
  ): Promise<QueuedJobDto> {
    const sd = await this.requireDomain(id);
    return {
      queued: true,
      jobId: await this.enqueuer.enqueue(
        { scannedDomainId: id, domain: sd.domain },
        true,
      ),
    };
  }

  @Get('screenshots/:id')
  @ApiOperation({ summary: 'One capture (metadata)' })
  @ApiOkResponse({ type: ScreenshotDto })
  @ApiNotFoundResponse()
  async get(@Param('id', ParseUUIDPipe) id: string): Promise<ScreenshotDto> {
    return toScreenshotDto(await this.query.get(id));
  }

  @Get('screenshots/:id/image')
  @ApiOperation({
    summary: 'Redirects (302) to a short-lived presigned URL for the PNG',
  })
  @ApiFoundResponse({ description: 'Location: presigned object URL' })
  @ApiNotFoundResponse({
    description: 'Unknown id or the capture failed (no image)',
  })
  async image(
    @Param('id', ParseUUIDPipe) id: string,
    @Res() res: Response,
  ): Promise<void> {
    const row = await this.query.get(id);
    if (!row.storageKey)
      throw new NotFoundException(
        `Screenshot ${id} has no image (${row.status})`,
      );
    res.setHeader('cache-control', 'no-store');
    res.redirect(
      HttpStatus.FOUND,
      await this.storage.getSignedUrl(row.storageKey),
    );
  }

  private async requireDomain(id: string) {
    const sd = await this.scannedDomains.getForEnrichment(id);
    if (!sd) throw new NotFoundException(`Scanned domain ${id} not found`);
    return sd;
  }
}
