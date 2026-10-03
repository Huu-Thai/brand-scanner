import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Post,
  Redirect,
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
import { ExpensiveThrottle } from '../../common/guards/api-key-throttler.guard.js';
import { PrismaService } from '../../database/prisma.service.js';
import { QueuedJobDto } from '../whois-informations/dto/whois-information.dto.js';
import { BrandReferenceService } from './brand-reference.service.js';

export class BrandReferenceDto {
  @ApiProperty({ format: 'uuid' }) originalDomainId: string;
  @ApiProperty({ enum: ['CAPTURED', 'FAILED'] }) status: string;
  @ApiPropertyOptional({ nullable: true }) perceptualHash: string | null;
  @ApiPropertyOptional({
    nullable: true,
    description: 'SHA-256 of the brand favicon',
  })
  faviconHash: string | null;
  @ApiPropertyOptional({ nullable: true }) pageTitle: string | null;
  @ApiPropertyOptional({ nullable: true }) finalUrl: string | null;
  @ApiPropertyOptional({ nullable: true }) errorMessage: string | null;
  @ApiPropertyOptional({ nullable: true }) capturedAt: Date | null;
  @ApiPropertyOptional({
    nullable: true,
    description: 'GET for a short-lived image URL',
  })
  imageUrl: string | null;
}

@ApiTags('screenshots')
@ApiSecurity('api-key')
@Controller('original-domains/:id/reference')
export class BrandReferenceController {
  constructor(
    private readonly references: BrandReferenceService,
    private readonly prisma: PrismaService,
  ) {}

  @Get()
  @ApiOperation({
    summary:
      "The brand site's reference capture (what look-alikes are compared against)",
  })
  @ApiOkResponse({ type: BrandReferenceDto })
  async get(
    @Param('id', ParseUUIDPipe) id: string,
  ): Promise<BrandReferenceDto> {
    const r = await this.references.get(id);
    return {
      originalDomainId: r.originalDomainId,
      status: r.status,
      perceptualHash: r.perceptualHash,
      faviconHash: r.faviconHash,
      pageTitle: r.pageTitle,
      finalUrl: r.finalUrl,
      errorMessage: r.errorMessage,
      capturedAt: r.capturedAt,
      imageUrl: r.storageKey
        ? `/api/v1/original-domains/${id}/reference/image`
        : null,
    };
  }

  @Get('image')
  @Redirect()
  @ApiOperation({
    summary: '302 to a short-lived URL of the reference screenshot',
  })
  async image(@Param('id', ParseUUIDPipe) id: string) {
    return { url: await this.references.imageUrl(id), statusCode: 302 };
  }

  @Post()
  @HttpCode(HttpStatus.ACCEPTED)
  @ExpensiveThrottle()
  @ApiOperation({ summary: 'Recapture the brand site now' })
  @ApiAcceptedResponse({ type: QueuedJobDto })
  async refresh(@Param('id', ParseUUIDPipe) id: string): Promise<QueuedJobDto> {
    if (
      !(await this.prisma.originalDomain.findFirst({
        where: { id, deletedAt: null },
        select: { id: true },
      }))
    )
      throw new NotFoundException(`Original domain ${id} not found`);
    return { queued: true, jobId: await this.references.enqueue(id, true) };
  }
}
