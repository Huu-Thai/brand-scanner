import { Module } from '@nestjs/common';
import { ThreatFeedModule } from '../../integrations/threat-feed/threat-feed.module.js';
import { ScannedDomainsModule } from '../scanned-domains/scanned-domains.module.js';
import { StatusSyncListener } from './listeners/status-sync.listener.js';
import { ThreatFeedPushEnqueuer } from './threat-feed-push.enqueuer.js';

/** Publishes confirmed look-alikes to threat-feed (shown in manage-feed). */
@Module({
  imports: [ThreatFeedModule, ScannedDomainsModule],
  providers: [StatusSyncListener, ThreatFeedPushEnqueuer],
  exports: [ThreatFeedPushEnqueuer],
})
export class ThreatFeedSyncModule {}
