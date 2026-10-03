import { Controller, Get, Param, ParseUUIDPipe } from '@nestjs/common';
import {
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import { InsightsService } from './insights.service.js';

@ApiTags('insights')
@ApiSecurity('api-key')
@Controller('scanned-domains/:id')
export class InsightsController {
  constructor(private readonly insights: InsightsService) {}

  @Get('related')
  @ApiOperation({
    summary:
      'Infrastructure graph: the brand, IPs, nameservers, mail servers and registrar of a look-alike, and other look-alikes sharing them',
  })
  @ApiOkResponse({ description: '{ nodes: GraphNode[], edges: GraphEdge[] }' })
  related(@Param('id', ParseUUIDPipe) id: string) {
    return this.insights.related(id);
  }

  @Get('timeline')
  @ApiOperation({
    summary:
      'Activity timeline: discovery, WHOIS, captures, risk changes, reviews and alerts (newest first)',
  })
  @ApiOkResponse({ description: 'TimelineEntry[]' })
  timeline(@Param('id', ParseUUIDPipe) id: string) {
    return this.insights.timeline(id);
  }
}
