import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Query,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import {
  CreateOriginalDomainDto,
  ListOriginalDomainsQueryDto,
  OriginalDomainDetailDto,
  OriginalDomainDto,
  OriginalDomainPageDto,
  UpdateOriginalDomainDto,
} from './dto/original-domain.dto.js';
import { OriginalDomainsService } from './original-domains.service.js';

@ApiTags('original-domains')
@ApiSecurity('api-key')
@Controller('original-domains')
export class OriginalDomainsController {
  constructor(private readonly service: OriginalDomainsService) {}

  @Post()
  @ApiOperation({
    summary:
      'Register a brand domain to monitor (restores it if previously deleted)',
  })
  @ApiCreatedResponse({ type: OriginalDomainDto })
  @ApiBadRequestResponse({ description: 'Invalid domain, schedule or options' })
  @ApiConflictResponse({ description: 'Domain already registered' })
  create(@Body() dto: CreateOriginalDomainDto): Promise<OriginalDomainDto> {
    return this.service.create(dto);
  }

  @Get()
  @ApiOperation({ summary: 'List original domains' })
  @ApiOkResponse({ type: OriginalDomainPageDto })
  findAll(@Query() query: ListOriginalDomainsQueryDto) {
    return this.service.findAll(query);
  }

  @Get(':id')
  @ApiOperation({
    summary:
      'Get an original domain with tracked look-alike counts and latest scan',
  })
  @ApiOkResponse({ type: OriginalDomainDetailDto })
  @ApiNotFoundResponse()
  findOne(
    @Param('id', ParseUUIDPipe) id: string,
  ): Promise<OriginalDomainDetailDto> {
    return this.service.findOne(id);
  }

  @Patch(':id')
  @ApiOperation({
    summary: 'Update label, schedule, default scan options or active flag',
  })
  @ApiOkResponse({ type: OriginalDomainDto })
  @ApiNotFoundResponse()
  update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateOriginalDomainDto,
  ): Promise<OriginalDomainDto> {
    return this.service.update(id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Soft-delete (stops schedules and cancels in-flight scans)',
  })
  @ApiNoContentResponse()
  @ApiNotFoundResponse()
  remove(@Param('id', ParseUUIDPipe) id: string): Promise<void> {
    return this.service.remove(id);
  }
}
