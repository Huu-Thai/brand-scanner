import { Body, Controller, Get, Param, Patch, Put } from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import { RequireScope } from '../../common/decorators/auth.decorators.js';
import { Principal } from '../../common/decorators/principal.decorator.js';
import type { ApiPrincipal } from '../../common/guards/api-key.guard.js';
import {
  RuleConfigDto,
  ScoringConfigDto,
  ScoringThresholdsDto,
  UpdateRuleConfigDto,
} from './dto/rule-config.dto.js';
import { RuleConfigsService } from './rule-configs.service.js';

@ApiTags('scoring')
@ApiSecurity('api-key')
@Controller('scoring')
export class RuleConfigsController {
  constructor(private readonly service: RuleConfigsService) {}

  @Get()
  @ApiOperation({
    summary: 'Scoring rules (tiers, params) and risk thresholds',
  })
  @ApiOkResponse({ type: ScoringConfigDto })
  get(): Promise<ScoringConfigDto> {
    return this.service.get();
  }

  @Patch('rules/:key')
  @RequireScope('admin')
  @ApiOperation({
    summary: 'Enable/disable a rule or change its point tiers / params (admin)',
  })
  @ApiOkResponse({ type: RuleConfigDto })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  update(
    @Param('key') key: string,
    @Body() dto: UpdateRuleConfigDto,
    @Principal() p: ApiPrincipal,
  ): Promise<RuleConfigDto> {
    return this.service.update(key, dto, p.name);
  }

  @Put('thresholds')
  @RequireScope('admin')
  @ApiOperation({ summary: 'Set the LOW / MEDIUM / HIGH risk bands (admin)' })
  @ApiOkResponse({ type: ScoringThresholdsDto })
  thresholds(
    @Body() dto: ScoringThresholdsDto,
    @Principal() p: ApiPrincipal,
  ): Promise<ScoringThresholdsDto> {
    return this.service.updateThresholds(dto, p.name);
  }
}
