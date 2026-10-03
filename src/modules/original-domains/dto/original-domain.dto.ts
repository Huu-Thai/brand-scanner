import {
  ApiProperty,
  ApiPropertyOptional,
  OmitType,
  PartialType,
} from '@nestjs/swagger';
import { Transform, Type } from 'class-transformer';
import {
  IsBoolean,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
  ValidateNested,
} from 'class-validator';
import {
  PageMetaDto,
  PaginationQueryDto,
} from '../../../common/dto/pagination.dto.js';
import { ScanOptionsDto } from '../../../common/dto/scan-options.dto.js';
import { IsCron } from '../../../common/validators/is-cron.validator.js';

const trim = ({ value }: { value: unknown }) =>
  typeof value === 'string' ? value.trim() : value;

export class CreateOriginalDomainDto {
  @ApiProperty({
    example: 'example.com',
    description: 'Brand domain to monitor (IDN accepted; stored as punycode)',
  })
  @IsString()
  @MinLength(3)
  @MaxLength(253)
  @Transform(trim)
  domain: string;

  @ApiPropertyOptional({ example: 'Example Corp — primary brand' })
  @IsOptional()
  @IsString()
  @MaxLength(120)
  @Transform(trim)
  label?: string;

  @ApiPropertyOptional({
    example: '0 2 * * *',
    description: 'Cron (UTC) for automatic scans; null/omitted = manual only',
  })
  @IsOptional()
  @IsCron()
  scanSchedule?: string | null;

  @ApiPropertyOptional({ type: ScanOptionsDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ScanOptionsDto)
  scanOptions?: ScanOptionsDto;

  @ApiPropertyOptional({ default: true })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}

/** The domain itself is immutable — tracked look-alikes are derived from it. */
export class UpdateOriginalDomainDto extends PartialType(
  OmitType(CreateOriginalDomainDto, ['domain'] as const),
) {}

export class ListOriginalDomainsQueryDto extends PaginationQueryDto {
  @ApiPropertyOptional({
    description: 'Case-insensitive substring of domain or label',
  })
  @IsOptional()
  @IsString()
  @MaxLength(253)
  search?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @Transform(({ value }) =>
    value === 'true' ? true : value === 'false' ? false : value,
  )
  @IsBoolean()
  isActive?: boolean;
}

export class OriginalDomainDto {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty({ example: 'xn--mnchen-3ya.info' }) domain: string;
  @ApiProperty({ example: 'münchen.info' }) unicodeDomain: string;
  @ApiPropertyOptional({ nullable: true }) label: string | null;
  @ApiProperty() isActive: boolean;
  @ApiPropertyOptional({ nullable: true, example: '0 2 * * *' }) scanSchedule:
    string | null;
  @ApiProperty({ type: ScanOptionsDto }) scanOptions: ScanOptionsDto;
  @ApiPropertyOptional({ nullable: true }) lastScannedAt: Date | null;
  @ApiProperty() createdAt: Date;
  @ApiProperty() updatedAt: Date;
}

export class OriginalDomainStatsDto {
  @ApiProperty({ example: 42 }) trackedDomains: number;
  @ApiProperty({
    example: { UNSCORED: 30, LOW_RISK: 8, MEDIUM_RISK: 3, HIGH_RISK: 1 },
  })
  byThreatLevel: Record<string, number>;
  @ApiPropertyOptional({
    nullable: true,
    description: 'Most recent scan (any status)',
  })
  latestScan: {
    id: string;
    status: string;
    createdAt: Date;
    finishedAt: Date | null;
  } | null;
}

export class OriginalDomainDetailDto extends OriginalDomainDto {
  @ApiProperty({ type: OriginalDomainStatsDto }) stats: OriginalDomainStatsDto;
}

export class OriginalDomainPageDto extends PageMetaDto {
  @ApiProperty({ type: [OriginalDomainDto] }) data: OriginalDomainDto[];
}
