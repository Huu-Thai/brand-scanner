import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsBoolean,
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  Length,
  Max,
  Min,
} from 'class-validator';
import {
  PageMetaDto,
  PaginationQueryDto,
} from '../../../common/dto/pagination.dto.js';
import {
  AlertChannelType,
  AlertDeliveryStatus,
  AlertEventType,
  AlertMode,
} from '../../../database/generated/prisma/enums.js';

const trim = ({ value }: { value: unknown }) =>
  typeof value === 'string' ? value.trim() : value;
const csv = ({ value }: { value: unknown }) =>
  typeof value === 'string' ? value.split(',') : value;

export class CreateAlertChannelDto {
  @ApiProperty({ example: 'SOC Slack' })
  @IsString()
  @Length(2, 100)
  @Transform(trim)
  name: string;

  @ApiProperty({ enum: AlertChannelType })
  @IsEnum(AlertChannelType)
  type: AlertChannelType;

  @ApiProperty({
    description:
      'WEBHOOK / SLACK: https URL (public address). EMAIL: comma-separated addresses (≤ 20). Stored encrypted.',
    example: 'https://hooks.slack.com/services/T000/B000/XXXX',
  })
  @IsString()
  @Length(3, 2_000)
  @Transform(trim)
  target: string;

  @ApiPropertyOptional({ default: true })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}

export class UpdateAlertChannelDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @Length(2, 100)
  @Transform(trim)
  name?: string;
  @ApiPropertyOptional({ description: 'Replaces the stored target' })
  @IsOptional()
  @IsString()
  @Length(3, 2_000)
  @Transform(trim)
  target?: string;
  @ApiPropertyOptional() @IsOptional() @IsBoolean() isActive?: boolean;
}

export class AlertChannelDto {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty() name: string;
  @ApiProperty({ enum: AlertChannelType }) type: AlertChannelType;
  @ApiProperty({
    example: 'https://hooks.slack.com/…XXXX',
    description: 'Masked; the full target is never returned',
  })
  targetHint: string;
  @ApiProperty() isActive: boolean;
  @ApiProperty({
    description: 'WEBHOOK: requests carry an X-Fuzzer-Signature HMAC',
  })
  signed: boolean;
  @ApiProperty() createdBy: string;
  @ApiProperty() createdAt: Date;
  @ApiProperty() updatedAt: Date;
}

export class AlertChannelWithSecretDto extends AlertChannelDto {
  @ApiPropertyOptional({
    description:
      'WEBHOOK only — shown ONCE (on create / rotate). Verify: hex(HMAC-SHA256(secret, `${X-Fuzzer-Timestamp}.${body}`))',
    example: 'whsec_…',
  })
  signingSecret?: string;
}

export class ChannelTestResultDto {
  @ApiProperty() ok: boolean;
  @ApiPropertyOptional() error?: string;
}

export class CreateAlertSubscriptionDto {
  @ApiProperty({ format: 'uuid' }) @IsUUID() channelId: string;

  @ApiPropertyOptional({ format: 'uuid', description: 'Omit for every brand' })
  @IsOptional()
  @IsUUID()
  originalDomainId?: string;

  @ApiProperty({
    enum: AlertEventType,
    isArray: true,
    example: ['HIGH_RISK', 'CONFIRMED_THREAT'],
  })
  @ArrayMinSize(1)
  @ArrayMaxSize(4)
  @IsEnum(AlertEventType, { each: true })
  eventTypes: AlertEventType[];

  @ApiPropertyOptional({
    default: 0,
    minimum: 0,
    maximum: 1000,
    description: 'Only look-alikes scoring at least this',
  })
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(1000)
  minRiskScore?: number;

  @ApiPropertyOptional({
    enum: AlertMode,
    default: AlertMode.IMMEDIATE,
    description: 'DIGEST: one message per day (ALERT_DIGEST_CRON)',
  })
  @IsOptional()
  @IsEnum(AlertMode)
  mode?: AlertMode;

  @ApiPropertyOptional({ default: true })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}

export class UpdateAlertSubscriptionDto {
  @ApiPropertyOptional({ enum: AlertEventType, isArray: true })
  @IsOptional()
  @ArrayMinSize(1)
  @ArrayMaxSize(4)
  @IsEnum(AlertEventType, { each: true })
  eventTypes?: AlertEventType[];
  @ApiPropertyOptional()
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(1000)
  minRiskScore?: number;
  @ApiPropertyOptional({ enum: AlertMode })
  @IsOptional()
  @IsEnum(AlertMode)
  mode?: AlertMode;
  @ApiPropertyOptional() @IsOptional() @IsBoolean() isActive?: boolean;
}

export class AlertSubscriptionDto {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty({ format: 'uuid' }) channelId: string;
  @ApiProperty() channelName: string;
  @ApiPropertyOptional({ format: 'uuid', nullable: true }) originalDomainId:
    string | null;
  @ApiPropertyOptional({ nullable: true, description: 'null = every brand' })
  brand: string | null;
  @ApiProperty({ enum: AlertEventType, isArray: true })
  eventTypes: AlertEventType[];
  @ApiProperty() minRiskScore: number;
  @ApiProperty({ enum: AlertMode }) mode: AlertMode;
  @ApiProperty() isActive: boolean;
  @ApiProperty() createdAt: Date;
}

export class ListAlertDeliveriesQueryDto extends PaginationQueryDto {
  @ApiPropertyOptional({ enum: AlertDeliveryStatus, isArray: true })
  @IsOptional()
  @Transform(csv)
  @IsEnum(AlertDeliveryStatus, { each: true })
  status?: AlertDeliveryStatus[];

  @ApiPropertyOptional({ enum: AlertEventType, isArray: true })
  @IsOptional()
  @Transform(csv)
  @IsEnum(AlertEventType, { each: true })
  eventType?: AlertEventType[];

  @ApiPropertyOptional({ format: 'uuid' })
  @IsOptional()
  @IsUUID()
  channelId?: string;
}

export class AlertDeliveryDto {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty({ format: 'uuid' }) channelId: string;
  @ApiProperty() channelName: string;
  @ApiProperty({ enum: AlertEventType }) eventType: AlertEventType;
  @ApiProperty({ enum: AlertMode }) mode: AlertMode;
  @ApiPropertyOptional({ format: 'uuid', nullable: true }) scannedDomainId:
    string | null;
  @ApiProperty() domain: string;
  @ApiProperty() brand: string;
  @ApiProperty() riskScore: number;
  @ApiProperty({ enum: AlertDeliveryStatus }) status: AlertDeliveryStatus;
  @ApiProperty() attempts: number;
  @ApiPropertyOptional({ nullable: true }) lastError: string | null;
  @ApiProperty() createdAt: Date;
  @ApiPropertyOptional({ nullable: true }) sentAt: Date | null;
}

export class AlertDeliveryPageDto extends PageMetaDto {
  @ApiProperty({ type: [AlertDeliveryDto] }) data: AlertDeliveryDto[];
}
