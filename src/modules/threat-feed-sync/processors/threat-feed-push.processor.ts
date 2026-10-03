import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { UnrecoverableError, type Job } from 'bullmq';
import { threatFeedPushTotal } from '../../../metrics/metrics.js';
import { withJobContext } from '../../../common/utils/job-context.js';
import { ReputationService } from '../../../integrations/threat-feed/reputation.service.js';
import {
  ThreatFeedClient,
  ThreatFeedError,
} from '../../../integrations/threat-feed/threat-feed.client.js';
import type { ThreatFeedPushJobData } from '../../../queue/jobs.js';
import { QUEUES } from '../../../queue/queue.constants.js';
import { ScannedDomainsQuery } from '../../scanned-domains/scanned-domains.query.js';
import { indicatorFor, PUBLISHED_STATUSES } from '../indicator.mapper.js';

export type PushOutcome =
  'created' | 'updated' | 'deactivated' | 'absent' | 'skipped';

/**
 * Converges the threat-feed indicator on the look-alike's *current* status, so retries and
 * out-of-order jobs are harmless: published status → active indicator, anything else → inactive.
 */
@Processor(QUEUES.THREAT_FEED_PUSH, { concurrency: 2 })
export class ThreatFeedPushProcessor extends WorkerHost {
  private readonly logger = new Logger(ThreatFeedPushProcessor.name);

  constructor(
    private readonly client: ThreatFeedClient,
    private readonly reputation: ReputationService,
    private readonly scannedDomains: ScannedDomainsQuery,
  ) {
    super();
  }

  process(job: Job<ThreatFeedPushJobData>) {
    return withJobContext(job, job.data.scannedDomainId, () =>
      this.run(job.data),
    );
  }

  async run(data: ThreatFeedPushJobData): Promise<{ outcome: PushOutcome }> {
    if (!this.client.enabled) return { outcome: 'skipped' };
    const row = await this.scannedDomains.getForEnrichment(
      data.scannedDomainId,
    );
    const publish = !!row && PUBLISHED_STATUSES.includes(row.status);
    const value = (row?.domain ?? data.domain).toLowerCase();

    try {
      const existing = await this.client.findIndicator('DOMAIN', value);
      let outcome: PushOutcome;
      if (publish) {
        const indicator = indicatorFor(row, await this.client.sourceId());
        if (existing) {
          const {
            sourceId: _ignored,
            value: _v,
            type: _t,
            ...changes
          } = indicator;
          // Keep tags others added in manage-feed.
          changes.tags = [
            ...new Set([...existing.tags, ...(changes.tags ?? [])]),
          ];
          await this.client.updateIndicator(existing.id, changes);
          outcome = 'updated';
        } else {
          await this.client.createIndicator(indicator);
          outcome = 'created';
        }
      } else if (existing?.isActive) {
        await this.client.updateIndicator(existing.id, { isActive: false });
        outcome = 'deactivated';
      } else {
        outcome = 'absent';
      }
      await this.reputation.invalidate('DOMAIN', value);
      threatFeedPushTotal.inc({ outcome });
      this.logger.log(
        `threat-feed ${value}: ${outcome} (requested ${data.action} by ${data.actor})`,
      );
      return { outcome };
    } catch (e) {
      threatFeedPushTotal.inc({ outcome: 'error' });
      // Permission and validation problems will not fix themselves — don't burn retries.
      if (
        e instanceof ThreatFeedError &&
        [400, 403, 404, 409, 422].includes(e.status ?? 0)
      )
        throw new UnrecoverableError(e.message);
      throw e;
    }
  }
}
