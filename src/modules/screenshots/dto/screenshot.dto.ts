import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ScreenshotStatus } from '../../../database/generated/prisma/enums.js';

export class ScreenshotDto {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty({ format: 'uuid' }) scannedDomainId: string;
  @ApiPropertyOptional({ format: 'uuid', nullable: true }) scanId:
    string | null;
  @ApiProperty({ enum: ScreenshotStatus }) status: ScreenshotStatus;
  @ApiProperty({ example: 'https://exampel.com/' }) requestedUrl: string;
  @ApiPropertyOptional({ nullable: true }) finalUrl: string | null;
  @ApiPropertyOptional({ nullable: true, example: 200 }) httpStatus:
    number | null;
  @ApiPropertyOptional({ nullable: true }) pageTitle: string | null;
  @ApiPropertyOptional({ nullable: true }) width: number | null;
  @ApiPropertyOptional({ nullable: true }) height: number | null;
  @ApiPropertyOptional({ nullable: true }) sizeBytes: number | null;
  @ApiPropertyOptional({
    nullable: true,
    example: 'c3c38f0f1f1f0e0c',
    description: '64-bit dHash',
  })
  perceptualHash: string | null;
  @ApiPropertyOptional({ nullable: true }) errorMessage: string | null;
  @ApiPropertyOptional({
    nullable: true,
    description: 'GET to receive a short-lived image URL',
  })
  imageUrl: string | null;
  @ApiPropertyOptional({ nullable: true }) capturedAt: Date | null;
  @ApiProperty() createdAt: Date;
}
