import { Module } from '@nestjs/common';
import { ThreatFeedModule } from '../../integrations/threat-feed/threat-feed.module.js';
import { RulesCacheListener } from './listeners/rules-cache.listener.js';
import {
  PhishingContentRule,
  VisualSimilarityRule,
} from './rules/content.rules.js';
import { RuleConfigsController } from './rule-configs.controller.js';
import { RuleConfigsService } from './rule-configs.service.js';
import { RuleEngineService } from './rule-engine.service.js';
import {
  DnsResolvesRule,
  DomainAgeRule,
  LevenshteinDistanceRule,
  LowTtlRule,
  MxRecordsFoundRule,
  SuspiciousTldRule,
} from './rules/local.rules.js';
import {
  DmarcMissingRule,
  ReputationCheckRule,
  SpamhausBlacklistRule,
  SslIssuesRule,
} from './rules/network.rules.js';

@Module({
  imports: [ThreatFeedModule],
  controllers: [RuleConfigsController],
  providers: [
    RuleEngineService,
    RuleConfigsService,
    RulesCacheListener,
    LevenshteinDistanceRule,
    SuspiciousTldRule,
    SslIssuesRule,
    DmarcMissingRule,
    DomainAgeRule,
    ReputationCheckRule,
    MxRecordsFoundRule,
    DnsResolvesRule,
    LowTtlRule,
    SpamhausBlacklistRule,
    VisualSimilarityRule,
    PhishingContentRule,
  ],
  exports: [RuleEngineService],
})
export class RulesModule {}
