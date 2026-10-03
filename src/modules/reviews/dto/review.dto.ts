import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  IsEnum,
  IsOptional,
  IsString,
  IsUUID,
  MaxLength,
} from 'class-validator';
import {
  PageMetaDto,
  PaginationQueryDto,
} from '../../../common/dto/pagination.dto.js';
import {
  DomainStatus,
  ReviewVerdict,
} from '../../../database/generated/prisma/enums.js';

export class CreateReviewDto {
  @ApiProperty({
    enum: ReviewVerdict,
    description:
      'MALICIOUS → CONFIRMED_THREAT (pushed to manage-feed) · SUSPICIOUS / NEEDS_INFO → UNDER_REVIEW · BENIGN → ACTIVE · FALSE_POSITIVE → FALSE_POSITIVE',
  })
  @IsEnum(ReviewVerdict)
  verdict: ReviewVerdict;

  @ApiPropertyOptional({
    example: 'Credential-harvesting kit cloned from the brand login page.',
    maxLength: 4000,
  })
  @IsOptional()
  @IsString()
  @MaxLength(4000)
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  notes?: string;
}

export class ListReviewsQueryDto extends PaginationQueryDto {
  @ApiPropertyOptional({ enum: ReviewVerdict, isArray: true })
  @IsOptional()
  @Transform(({ value }) =>
    typeof value === 'string' ? value.split(',') : value,
  )
  @IsEnum(ReviewVerdict, { each: true })
  verdict?: ReviewVerdict[];

  @ApiPropertyOptional({ example: 'analyst@example.com' })
  @IsOptional()
  @IsString()
  @MaxLength(254)
  reviewer?: string;

  @ApiPropertyOptional({ format: 'uuid' })
  @IsOptional()
  @IsUUID()
  originalDomainId?: string;
}

export class ReviewDto {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty({ format: 'uuid' }) scannedDomainId: string;
  @ApiPropertyOptional({ example: 'apypal.com' }) domain?: string;
  @ApiProperty({ enum: ReviewVerdict }) verdict: ReviewVerdict;
  @ApiPropertyOptional({ nullable: true }) notes: string | null;
  @ApiProperty({ example: 'analyst@example.com' }) reviewer: string;
  @ApiProperty({ enum: DomainStatus }) previousStatus: DomainStatus;
  @ApiProperty({ enum: DomainStatus }) newStatus: DomainStatus;
  @ApiProperty() createdAt: Date;
}

export class ReviewPageDto extends PageMetaDto {
  @ApiProperty({ type: [ReviewDto] }) data: ReviewDto[];
}
