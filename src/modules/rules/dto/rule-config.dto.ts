import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  ArrayMaxSize,
  IsArray,
  IsBoolean,
  IsInt,
  IsObject,
  IsOptional,
  IsString,
  Max,
  MaxLength,
  Min,
  ValidateNested,
} from 'class-validator';

export class RulePointTierDto {
  @ApiProperty({ example: 'found' })
  @IsString()
  @MaxLength(50)
  condition: string;

  @ApiProperty({ example: 40, minimum: 0, maximum: 1000 })
  @IsInt()
  @Min(0)
  @Max(1000)
  points: number;
}

export class UpdateRuleConfigDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  @ApiPropertyOptional({
    type: [RulePointTierDto],
    description: 'Replaces all tiers. Include a "default" tier.',
  })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @ValidateNested({ each: true })
  @Type(() => RulePointTierDto)
  points?: RulePointTierDto[];

  @ApiPropertyOptional({
    example: { tlds: ['.tk', '.top'] },
    description: 'Rule-specific parameters (replaces all)',
  })
  @IsOptional()
  @IsObject()
  params?: Record<string, unknown>;
}

export class RuleConfigDto {
  @ApiProperty({ example: 'reputation_check' }) key: string;
  @ApiProperty({ example: 'Reputation Check' }) name: string;
  @ApiProperty() enabled: boolean;
  @ApiProperty({ type: [RulePointTierDto] }) points: RulePointTierDto[];
  @ApiProperty({ example: { provider: 'threat-feed' } }) params: Record<
    string,
    unknown
  >;
}

export class ScoringThresholdsDto {
  @ApiProperty({ example: 80, description: 'Score ≥ this → HIGH_RISK' })
  @IsInt()
  @Min(1)
  @Max(10_000)
  thresholdMediumRisk: number;

  @ApiProperty({ example: 40, description: 'Score < this → LOW_RISK' })
  @IsInt()
  @Min(1)
  @Max(10_000)
  thresholdLowRisk: number;
}

export class ScoringConfigDto {
  @ApiProperty({ type: [RuleConfigDto] }) rules: RuleConfigDto[];
  @ApiProperty({ type: ScoringThresholdsDto }) thresholds: ScoringThresholdsDto;
}
