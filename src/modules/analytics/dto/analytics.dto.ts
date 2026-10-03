import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsInt, IsOptional, IsUUID, Max, Min } from 'class-validator';
import { ThreatLevel } from '../../../database/generated/prisma/enums.js';

export class RuleResultDto {
  @ApiProperty({ example: 'domain_age' }) key: string;
  @ApiProperty() matched: boolean;
  @ApiPropertyOptional({ nullable: true, example: '30' }) condition:
    string | null;
  @ApiPropertyOptional({
    nullable: true,
    example: 12,
    description: 'Raw signal behind the condition',
  })
  value: string | number | boolean | null;
  @ApiProperty({ example: 20 }) points: number;
}

export class AnalyticsDto {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty({ format: 'uuid' }) scannedDomainId: string;
  @ApiPropertyOptional({ format: 'uuid', nullable: true }) scanId:
    string | null;
  @ApiProperty({ example: 95 }) totalScore: number;
  @ApiProperty({ enum: ThreatLevel }) threatLevel: ThreatLevel;
  @ApiProperty({ type: [RuleResultDto] }) ruleResults: RuleResultDto[];
  @ApiPropertyOptional({ nullable: true }) levenshteinDistance: number | null;
  @ApiPropertyOptional({ nullable: true }) domainAgeDays: number | null;
  @ApiPropertyOptional({ nullable: true }) sslStatus: string | null;
  @ApiPropertyOptional({ nullable: true }) dmarcPolicy: string | null;
  @ApiPropertyOptional({ nullable: true }) hasMx: boolean | null;
  @ApiPropertyOptional({ nullable: true }) spamhausListed: boolean | null;
  @ApiPropertyOptional({
    nullable: true,
    description: 'null = reputation source unavailable',
  })
  reputationHit: boolean | null;
  @ApiProperty() computedAt: Date;
}

export class SummaryQueryDto {
  @ApiPropertyOptional({ format: 'uuid' })
  @IsOptional()
  @IsUUID()
  originalDomainId?: string;
}

export class TrendsQueryDto extends SummaryQueryDto {
  @ApiPropertyOptional({ default: 30, minimum: 1, maximum: 365 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(365)
  days: number = 30;
}

export class SummaryDto {
  @ApiProperty() total: number;
  @ApiProperty({
    example: { UNSCORED: 2, LOW_RISK: 40, MEDIUM_RISK: 9, HIGH_RISK: 3 },
  })
  byThreatLevel: Record<string, number>;
  @ApiProperty({ example: { NEW: 30, ACTIVE: 20, INACTIVE: 4 } })
  byStatus: Record<string, number>;
  @ApiProperty({ example: { homoglyph: 12, omission: 5 } }) byFuzzer: Record<
    string,
    number
  >;
}

export class TrendPointDto {
  @ApiProperty({ example: '2026-10-02' }) date: string;
  @ApiProperty({ description: 'Look-alikes first seen that day' })
  newLookalikes: number;
  @ApiProperty({
    description: 'Distinct look-alikes scored HIGH_RISK that day',
  })
  highRisk: number;
}
