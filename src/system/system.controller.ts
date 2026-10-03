import { Controller, Get } from '@nestjs/common';
import {
  ApiOkResponse,
  ApiOperation,
  ApiProperty,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import { Principal } from '../common/decorators/principal.decorator.js';
import type { ApiPrincipal } from '../common/guards/api-key.guard.js';
import { ALL_QUEUES } from '../queue/queue.constants.js';

class SystemInfoDto {
  @ApiProperty({ example: 'fuzzer-scanner' }) name: string;
  @ApiProperty({ example: '0.1.0' }) version: string;
  @ApiProperty({ example: 3600 }) uptimeSeconds: number;
  @ApiProperty({
    example: 'ci-reader',
    description: 'Name of the API key used',
  })
  caller: string;
  @ApiProperty({ type: [String] }) queues: string[];
}

@ApiTags('system')
@ApiSecurity('api-key')
@Controller('system')
export class SystemController {
  @Get('info')
  @ApiOperation({
    summary: 'Service metadata; also verifies the caller’s API key',
  })
  @ApiOkResponse({ type: SystemInfoDto })
  info(@Principal() principal: ApiPrincipal): SystemInfoDto {
    return {
      name: 'fuzzer-scanner',
      version: process.env.npm_package_version ?? '0.1.0',
      uptimeSeconds: Math.round(process.uptime()),
      caller: principal.name,
      queues: ALL_QUEUES,
    };
  }
}
