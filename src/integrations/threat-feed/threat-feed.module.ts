import { Module } from '@nestjs/common';
import { ReputationService } from './reputation.service.js';
import { ThreatFeedClient } from './threat-feed.client.js';

@Module({
  providers: [ThreatFeedClient, ReputationService],
  exports: [ReputationService, ThreatFeedClient],
})
export class ThreatFeedModule {}
