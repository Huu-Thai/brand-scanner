import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform, Type } from 'class-transformer';
import {
  IsDateString,
  IsEnum,
  IsOptional,
  IsString,
  IsUUID,
  MaxLength,
  ValidateIf,
  ValidateNested,
} from 'class-validator';
import {
  PageMetaDto,
  PaginationQueryDto,
} from '../../../common/dto/pagination.dto.js';
import { ScanOptionsDto } from '../../../common/dto/scan-options.dto.js';
import {
  ScanStatus,
  ScanTrigger,
} from '../../../database/generated/prisma/enums.js';

export class CreateScanDto {
  @ApiPropertyOptional({
    format: 'uuid',
    description: 'Original domain to scan (or pass `domain`)',
  })
  @ValidateIf((o: CreateScanDto) => !o.domain)
  @IsUUID()
  originalDomainId?: string;

  @ApiPropertyOptional({
    example: 'example.com',
    description: 'Registered original domain name (alternative to the id)',
  })
  @ValidateIf((o: CreateScanDto) => !o.originalDomainId)
  @IsString()
  @MaxLength(253)
  domain?: string;

  @ApiPropertyOptional({
    type: ScanOptionsDto,
    description: 'Overrides the original domain’s default scanOptions',
  })
  @IsOptional()
  @ValidateNested()
  @Type(() => ScanOptionsDto)
  options?: ScanOptionsDto;
}

export class TriggerScanDto {
  @ApiPropertyOptional({ type: ScanOptionsDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ScanOptionsDto)
  options?: ScanOptionsDto;
}

export class ListScansQueryDto extends PaginationQueryDto {
  @ApiPropertyOptional({ format: 'uuid' })
  @IsOptional()
  @IsUUID()
  originalDomainId?: string;

  @ApiPropertyOptional({ enum: ScanStatus, isArray: true })
  @IsOptional()
  @Transform(({ value }) =>
    typeof value === 'string' ? value.split(',') : value,
  )
  @IsEnum(ScanStatus, { each: true })
  status?: ScanStatus[];

  @ApiPropertyOptional({ description: 'Created at or after (ISO 8601)' })
  @IsOptional()
  @IsDateString()
  from?: string;

  @ApiPropertyOptional({ description: 'Created before (ISO 8601)' })
  @IsOptional()
  @IsDateString()
  to?: string;
}

export class ScanDto {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty({ format: 'uuid' }) originalDomainId: string;
  @ApiProperty({ enum: ScanStatus }) status: ScanStatus;
  @ApiProperty({ enum: ScanTrigger }) triggeredBy: ScanTrigger;
  @ApiProperty({ type: ScanOptionsDto }) options: ScanOptionsDto;
  @ApiProperty() permutationsTotal: number;
  @ApiProperty() resolvedCount: number;
  @ApiProperty() registeredCount: number;
  @ApiProperty({ description: 'Look-alikes first seen in this scan' })
  newCount: number;
  @ApiProperty({
    description: 'Permutations whose DNS batch failed after retries',
  })
  failedCount: number;
  @ApiProperty({
    example: 42.5,
    description: 'resolvedCount / permutationsTotal × 100',
  })
  progressPercent: number;
  @ApiPropertyOptional({ nullable: true }) errorMessage: string | null;
  @ApiPropertyOptional({ nullable: true }) startedAt: Date | null;
  @ApiPropertyOptional({ nullable: true }) finishedAt: Date | null;
  @ApiProperty() createdAt: Date;
  @ApiProperty() updatedAt: Date;
}

export class ScanPageDto extends PageMetaDto {
  @ApiProperty({ type: [ScanDto] }) data: ScanDto[];
}
