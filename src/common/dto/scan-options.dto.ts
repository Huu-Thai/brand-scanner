import { ApiPropertyOptional } from '@nestjs/swagger';
import {
  ArrayUnique,
  IsArray,
  IsBoolean,
  IsIn,
  IsOptional,
} from 'class-validator';
import {
  FUZZERS,
  type FuzzerName,
} from '../../modules/fuzzer/fuzzer.constants.js';

/** Per-scan options; also stored as an original domain's default `scanOptions`. */
export class ScanOptionsDto {
  @ApiPropertyOptional({
    enum: FUZZERS,
    isArray: true,
    description:
      'Restrict to these techniques. Omit for all. Subset scans never mark unseen domains inactive.',
    example: ['omission', 'transposition', 'homoglyph'],
  })
  @IsOptional()
  @IsArray()
  @ArrayUnique()
  @IsIn(FUZZERS, { each: true })
  fuzzers?: FuzzerName[];

  @ApiPropertyOptional({
    default: true,
    description: 'Collect WHOIS/RDAP for registered domains (Phase 2)',
  })
  @IsOptional()
  @IsBoolean()
  includeWhois?: boolean;

  @ApiPropertyOptional({
    default: true,
    description: 'Capture screenshots for resolving domains (Phase 2)',
  })
  @IsOptional()
  @IsBoolean()
  includeScreenshots?: boolean;
}
