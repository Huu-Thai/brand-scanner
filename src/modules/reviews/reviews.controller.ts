import {
  Body,
  Controller,
  Get,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
} from '@nestjs/common';
import {
  ApiCreatedResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import { Principal } from '../../common/decorators/principal.decorator.js';
import type { ApiPrincipal } from '../../common/guards/api-key.guard.js';
import { ScannedDomainsQuery } from '../scanned-domains/scanned-domains.query.js';
import {
  CreateReviewDto,
  ListReviewsQueryDto,
  ReviewDto,
  ReviewPageDto,
} from './dto/review.dto.js';
import { ReviewsService } from './reviews.service.js';

@ApiTags('reviews')
@ApiSecurity('api-key')
@Controller()
export class ReviewsController {
  constructor(
    private readonly reviews: ReviewsService,
    private readonly scannedDomains: ScannedDomainsQuery,
  ) {}

  @Post('scanned-domains/:id/reviews')
  @ApiOperation({
    summary: 'Record an analyst verdict',
    description:
      'The look-alike status follows the verdict; MALICIOUS also publishes it as an indicator in manage-feed.',
  })
  @ApiCreatedResponse({ type: ReviewDto })
  @ApiNotFoundResponse()
  create(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: CreateReviewDto,
    @Principal() p: ApiPrincipal,
  ): Promise<ReviewDto> {
    return this.reviews.create(id, dto, p.actor);
  }

  @Get('scanned-domains/:id/reviews')
  @ApiOperation({ summary: 'Review history of a look-alike (newest first)' })
  @ApiOkResponse({ type: [ReviewDto] })
  async forDomain(
    @Param('id', ParseUUIDPipe) id: string,
  ): Promise<ReviewDto[]> {
    if (!(await this.scannedDomains.getForEnrichment(id)))
      throw new NotFoundException(`Scanned domain ${id} not found`);
    return this.reviews.forDomain(id);
  }

  @Get('reviews')
  @ApiOperation({
    summary:
      'All reviews (audit trail), filterable by verdict, reviewer and brand',
  })
  @ApiOkResponse({ type: ReviewPageDto })
  findAll(@Query() q: ListReviewsQueryDto) {
    return this.reviews.findAll(q);
  }
}
