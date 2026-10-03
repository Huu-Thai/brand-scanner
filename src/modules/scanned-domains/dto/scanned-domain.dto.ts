import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  ArrayUnique,
  IsArray,
  IsEnum,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  Max,
  MaxLength,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';
import {
  PageMetaDto,
  PaginationQueryDto,
} from '../../../common/dto/pagination.dto.js';
import {
  DomainStatus,
  ThreatLevel,
} from '../../../database/generated/prisma/enums.js';
import { FUZZERS } from '../../fuzzer/fuzzer.constants.js';
import { MANUAL_TARGETS } from '../status-rules.js';

const csv = ({ value }: { value: unknown }) =>
  typeof value === 'string' ? value.split(',') : value;

export const SCANNED_DOMAIN_SORT = [
  'firstSeenAt',
  'lastSeenAt',
  'riskScore',
  'domain',
] as const;

export class ListScannedDomainsQueryDto extends PaginationQueryDto {
  @ApiPropertyOptional({ format: 'uuid' })
  @IsOptional()
  @IsUUID()
  originalDomainId?: string;

  @ApiPropertyOptional({
    format: 'uuid',
    description: 'Domains seen in this scan',
  })
  @IsOptional()
  @IsUUID()
  scanId?: string;

  @ApiPropertyOptional({ enum: DomainStatus, isArray: true })
  @IsOptional()
  @Transform(csv)
  @IsEnum(DomainStatus, { each: true })
  status?: DomainStatus[];

  @ApiPropertyOptional({ enum: ThreatLevel, isArray: true })
  @IsOptional()
  @Transform(csv)
  @IsEnum(ThreatLevel, { each: true })
  threatLevel?: ThreatLevel[];

  @ApiPropertyOptional({ enum: FUZZERS, isArray: true })
  @IsOptional()
  @Transform(csv)
  @IsIn(FUZZERS, { each: true })
  fuzzer?: string[];

  @ApiPropertyOptional({ minimum: 0, maximum: 1000 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(1000)
  minScore?: number;

  @ApiPropertyOptional({
    description: 'Substring of the domain (ASCII or Unicode)',
  })
  @IsOptional()
  @IsString()
  @MaxLength(253)
  search?: string;

  @ApiPropertyOptional({ enum: SCANNED_DOMAIN_SORT, default: 'firstSeenAt' })
  @IsOptional()
  @IsIn(SCANNED_DOMAIN_SORT)
  sort: (typeof SCANNED_DOMAIN_SORT)[number] = 'firstSeenAt';
}

export class ScannedDomainDto {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty({ format: 'uuid' }) originalDomainId: string;
  @ApiPropertyOptional({ format: 'uuid', nullable: true }) lastScanId:
    string | null;
  @ApiProperty({ example: 'exampel.com' }) domain: string;
  @ApiProperty({ example: 'exampel.com' }) unicodeDomain: string;
  @ApiProperty({ example: 'transposition' }) fuzzer: string;
  @ApiProperty({ type: [String] }) dnsA: string[];
  @ApiProperty({ type: [String] }) dnsAaaa: string[];
  @ApiProperty({ type: [String] }) dnsMx: string[];
  @ApiProperty({ type: [String] }) dnsNs: string[];
  @ApiPropertyOptional({ nullable: true }) dnsTtl: number | null;
  @ApiProperty({ type: [String], example: [] }) dnsErrors: string[];
  @ApiProperty({ enum: DomainStatus }) status: DomainStatus;
  @ApiProperty() riskScore: number;
  @ApiProperty({ enum: ThreatLevel }) threatLevel: ThreatLevel;
  @ApiProperty({ type: [String] }) tags: string[];
  @ApiProperty() firstSeenAt: Date;
  @ApiProperty() lastSeenAt: Date;
  @ApiProperty() createdAt: Date;
  @ApiProperty() updatedAt: Date;
  @ApiPropertyOptional({
    example: 'paypal.com',
    description: 'The brand this look-alike imitates (detail view)',
  })
  originalDomain?: string;
}

export class ScannedDomainPageDto extends PageMetaDto {
  @ApiProperty({ type: [ScannedDomainDto] }) data: ScannedDomainDto[];
}

/** The filter fields shared by list and export. */
export type ScannedDomainFilters = Pick<
  ListScannedDomainsQueryDto,
  | 'originalDomainId'
  | 'scanId'
  | 'status'
  | 'threatLevel'
  | 'fuzzer'
  | 'minScore'
  | 'search'
>;

const TAG = /^[a-z0-9][a-z0-9:._-]{0,49}$/i;

export class ScannedDomainChangesDto {
  @ApiPropertyOptional({
    enum: MANUAL_TARGETS,
    description:
      'Analyst status. TAKEN_DOWN only from CONFIRMED_THREAT; ACTIVE reopens an analyst decision.',
  })
  @IsOptional()
  @IsIn(MANUAL_TARGETS)
  status?: DomainStatus;

  @ApiPropertyOptional({ type: [String], example: ['takedown-requested'] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @Matches(TAG, {
    each: true,
    message: 'tags must be 1–50 chars of [a-z0-9:._-]',
  })
  addTags?: string[];

  @ApiPropertyOptional({ type: [String] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @IsString({ each: true })
  removeTags?: string[];
}

export class BulkUpdateScannedDomainsDto extends ScannedDomainChangesDto {
  @ApiProperty({ type: [String], format: 'uuid', maxItems: 500 })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(500)
  @ArrayUnique()
  @IsUUID('all', { each: true })
  ids: string[];
}

export class BulkUpdateResultDto {
  @ApiProperty() statusChanged: number;
  @ApiProperty() tagsUpdated: number;
}

export const EXPORT_FORMATS = ['csv', 'json', 'stix'] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

export class ExportScannedDomainsQueryDto {
  @ApiPropertyOptional({ enum: EXPORT_FORMATS, default: 'csv' })
  @IsOptional()
  @IsIn(EXPORT_FORMATS)
  format: ExportFormat = 'csv';

  @ApiPropertyOptional({ format: 'uuid' })
  @IsOptional()
  @IsUUID()
  originalDomainId?: string;

  @ApiPropertyOptional({ format: 'uuid' })
  @IsOptional()
  @IsUUID()
  scanId?: string;

  @ApiPropertyOptional({ enum: DomainStatus, isArray: true })
  @IsOptional()
  @Transform(csv)
  @IsEnum(DomainStatus, { each: true })
  status?: DomainStatus[];

  @ApiPropertyOptional({ enum: ThreatLevel, isArray: true })
  @IsOptional()
  @Transform(csv)
  @IsEnum(ThreatLevel, { each: true })
  threatLevel?: ThreatLevel[];

  @ApiPropertyOptional({ enum: FUZZERS, isArray: true })
  @IsOptional()
  @Transform(csv)
  @IsIn(FUZZERS, { each: true })
  fuzzer?: string[];

  @ApiPropertyOptional()
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  minScore?: number;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(253)
  search?: string;
}
