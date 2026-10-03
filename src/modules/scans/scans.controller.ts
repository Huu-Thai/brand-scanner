import { ExpensiveThrottle } from '../../common/guards/api-key-throttler.guard.js';
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
  Res,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiConflictResponse,
  ApiHeader,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
  ApiUnprocessableEntityResponse,
} from '@nestjs/swagger';
import type { Response } from 'express';
import { API_PREFIX } from '../../common/constants/api.constants.js';
import {
  InvalidDomainError,
  normalizeDomain,
} from '../../common/utils/domain.js';
import { ScanTrigger } from '../../database/generated/prisma/enums.js';
import { OriginalDomainsQuery } from '../original-domains/original-domains.query.js';
import {
  CreateScanDto,
  ListScansQueryDto,
  ScanDto,
  ScanPageDto,
  TriggerScanDto,
} from './dto/scan.dto.js';
import { toScanDto } from './scans.mapper.js';
import { type CreateScanResult, ScansService } from './scans.service.js';

const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,128}$/;

const idempotencyHeader = {
  name: 'Idempotency-Key',
  required: false,
  description:
    'Retry-safe key (8–128 chars). Repeating a request with the same key returns the same scan.',
};

@ApiTags('scans')
@ApiSecurity('api-key')
@Controller()
export class ScansController {
  constructor(
    private readonly scans: ScansService,
    private readonly originalDomains: OriginalDomainsQuery,
  ) {}

  @ExpensiveThrottle()
  @Post('scans')
  @ApiOperation({
    summary: 'Trigger a scan',
    description:
      'Returns 202 with the new scan, or 200 with the scan already in progress for that domain (at most one runs at a time).',
  })
  @ApiHeader(idempotencyHeader)
  @ApiAcceptedResponse({ type: ScanDto, description: 'Scan queued' })
  @ApiOkResponse({
    type: ScanDto,
    description: 'Existing in-flight scan (or idempotent replay)',
  })
  @ApiNotFoundResponse({ description: 'Original domain not registered' })
  @ApiUnprocessableEntityResponse({
    description: 'Original domain is inactive',
  })
  @ApiConflictResponse({
    description: 'Idempotency-Key reused for another domain',
  })
  async create(
    @Body() dto: CreateScanDto,
    @Headers('idempotency-key') idempotencyKey: string | undefined,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ScanDto> {
    const originalDomainId =
      dto.originalDomainId ?? (await this.resolveDomain(dto.domain!));
    return this.respond(
      res,
      await this.scans.create({
        originalDomainId,
        options: dto.options,
        triggeredBy: ScanTrigger.API,
        idempotencyKey: this.checkKey(idempotencyKey),
      }),
    );
  }

  @ExpensiveThrottle()
  @Post('original-domains/:id/scans')
  @ApiOperation({ summary: 'Trigger a scan for an original domain (shortcut)' })
  @ApiHeader(idempotencyHeader)
  @ApiAcceptedResponse({ type: ScanDto })
  @ApiOkResponse({ type: ScanDto, description: 'Existing in-flight scan' })
  @ApiNotFoundResponse()
  async trigger(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: TriggerScanDto,
    @Headers('idempotency-key') idempotencyKey: string | undefined,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ScanDto> {
    return this.respond(
      res,
      await this.scans.create({
        originalDomainId: id,
        options: dto.options,
        triggeredBy: ScanTrigger.API,
        idempotencyKey: this.checkKey(idempotencyKey),
      }),
    );
  }

  @Get('scans')
  @ApiOperation({ summary: 'List scans' })
  @ApiOkResponse({ type: ScanPageDto })
  findAll(@Query() query: ListScansQueryDto) {
    return this.scans.findAll(query);
  }

  @Get('scans/:id')
  @ApiOperation({
    summary: 'Scan status and progress (poll this after triggering)',
  })
  @ApiOkResponse({ type: ScanDto })
  @ApiNotFoundResponse()
  async findOne(@Param('id', ParseUUIDPipe) id: string): Promise<ScanDto> {
    return toScanDto(await this.scans.get(id));
  }

  @Post('scans/:id/cancel')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Cancel an in-flight scan (remaining DNS batches are skipped)',
  })
  @ApiOkResponse({ type: ScanDto })
  @ApiConflictResponse({ description: 'Scan already finished' })
  async cancel(@Param('id', ParseUUIDPipe) id: string): Promise<ScanDto> {
    return toScanDto(await this.scans.cancel(id));
  }

  private respond(res: Response, { scan, created }: CreateScanResult): ScanDto {
    res.status(created ? HttpStatus.ACCEPTED : HttpStatus.OK);
    res.setHeader('Location', `/${API_PREFIX}/scans/${scan.id}`);
    return toScanDto(scan);
  }

  private checkKey(key: string | undefined): string | undefined {
    if (key === undefined) return undefined;
    if (!IDEMPOTENCY_KEY.test(key)) {
      throw new BadRequestException(
        'Idempotency-Key must be 8-128 characters of [A-Za-z0-9._:-]',
      );
    }
    return key;
  }

  private async resolveDomain(domain: string): Promise<string> {
    let ascii: string;
    try {
      ascii = normalizeDomain(domain).ascii;
    } catch (e) {
      if (e instanceof InvalidDomainError)
        throw new BadRequestException(e.message);
      throw e;
    }
    const original = await this.originalDomains.findByDomain(ascii);
    if (!original) {
      throw new NotFoundException(
        `${domain} is not a registered original domain — create it via POST /original-domains first`,
      );
    }
    return original.id;
  }
}
