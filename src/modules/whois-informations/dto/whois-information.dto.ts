import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { WhoisSource } from '../../../database/generated/prisma/enums.js';

export class WhoisInformationDto {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty({ format: 'uuid' }) scannedDomainId: string;
  @ApiProperty({ enum: WhoisSource }) source: WhoisSource;
  @ApiPropertyOptional({ nullable: true, example: 'NameCheap, Inc.' })
  registrar: string | null;
  @ApiPropertyOptional({ nullable: true }) registrantOrg: string | null;
  @ApiPropertyOptional({ nullable: true, example: 'IS' }) registrantCountry:
    string | null;
  @ApiPropertyOptional({ nullable: true, example: 'abuse@namecheap.com' })
  abuseEmail: string | null;
  @ApiProperty({ type: [String] }) emails: string[];
  @ApiProperty({ type: [String] }) nameServers: string[];
  @ApiProperty({ type: [String] }) statuses: string[];
  @ApiPropertyOptional({ nullable: true }) dnssec: string | null;
  @ApiPropertyOptional({ nullable: true }) whoisServer: string | null;
  @ApiPropertyOptional({ nullable: true }) createdDate: Date | null;
  @ApiPropertyOptional({ nullable: true }) updatedDate: Date | null;
  @ApiPropertyOptional({ nullable: true }) expiresDate: Date | null;
  @ApiPropertyOptional({
    nullable: true,
    description: 'Domain age in days at fetch time',
  })
  domainAgeDays: number | null;
  @ApiProperty() parseSucceeded: boolean;
  @ApiProperty() fetchedAt: Date;
  @ApiPropertyOptional({
    nullable: true,
    description: 'Raw RDAP JSON / WHOIS text (detail endpoint only)',
  })
  rawText?: string | null;
}

export class QueuedJobDto {
  @ApiProperty({ example: true }) queued: boolean;
  @ApiProperty({ example: 'whois-…-manual-1696230000000' }) jobId: string;
}
