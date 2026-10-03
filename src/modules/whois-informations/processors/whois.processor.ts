import { OnWorkerEvent, Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { DelayedError, type Job } from 'bullmq';
import { withJobContext } from '../../../common/utils/job-context.js';
import type { AppConfig } from '../../../config/configuration.js';
import type { WhoisJobData } from '../../../queue/jobs.js';
import { QUEUES } from '../../../queue/queue.constants.js';
import { ScannedDomainsQuery } from '../../scanned-domains/scanned-domains.query.js';
import {
  WHOIS_EVENTS,
  WhoisInformationFailedEvent,
} from '../events/whois-information.events.js';
import { HostBusyError } from '../lookup/rate-limiter.js';
import { WhoisLookupService } from '../lookup/whois-lookup.service.js';
import { WhoisInformationsQuery } from '../whois-informations.query.js';
import { WhoisInformationsService } from '../whois-informations.service.js';

/**
 * WHOIS/RDAP for one look-alike. Registries are protected per host by the RDAP client's windows;
 * the BullMQ limiter only bounds bursts (incl. jobs re-parked because their registry was busy).
 */
@Processor(QUEUES.WHOIS, {
  concurrency: 4,
  limiter: { max: 20, duration: 1_000 },
})
export class WhoisProcessor extends WorkerHost {
  private readonly logger = new Logger(WhoisProcessor.name);

  constructor(
    private readonly lookup: WhoisLookupService,
    private readonly service: WhoisInformationsService,
    private readonly query: WhoisInformationsQuery,
    private readonly scannedDomains: ScannedDomainsQuery,
    private readonly events: EventEmitter2,
    private readonly config: ConfigService<AppConfig, true>,
  ) {
    super();
  }

  process(job: Job<WhoisJobData>, token?: string) {
    return withJobContext(job, job.data.scanId, async () => {
      const { scannedDomainId, domain, scanId, force } = job.data;
      if (!(await this.scannedDomains.getForEnrichment(scannedDomainId)))
        return { skipped: 'scanned domain gone' };

      const days = this.config.get('enrichment', {
        infer: true,
      }).whoisRefreshDays;
      if (!force && !(await this.query.isStale(scannedDomainId, days))) {
        return { skipped: 'fresh snapshot exists' };
      }

      let result;
      try {
        result = await this.lookup.lookup(domain);
      } catch (e) {
        if (!(e instanceof HostBusyError) || !token) throw e;
        // The registry's window is full: park the job (no attempt used) and free this slot for
        // look-alikes on other registries.
        const bounces = (job.data.busyBounces ?? 0) + 1;
        await job.updateData({ ...job.data, busyBounces: bounces });
        await job.moveToDelayed(
          Date.now() + busyDelayMs(e.retryAfterMs, bounces),
          token,
        );
        throw new DelayedError();
      }
      const row = await this.service.create(scannedDomainId, result, scanId);
      this.logger.debug(
        `WHOIS ${domain} via ${result.source}: ${result.parseSucceeded ? 'parsed' : 'no data'}`,
      );
      return {
        whoisInformationId: row.id,
        source: result.source,
        parseSucceeded: result.parseSucceeded,
      };
    });
  }

  /** After the final attempt, let scoring proceed without WHOIS signals. */
  @OnWorkerEvent('failed')
  onFailed(job: Job<WhoisJobData>, error: Error): void {
    if (job.attemptsMade < (job.opts.attempts ?? 1)) return;
    this.logger.warn(`WHOIS gave up for ${job.data.domain}: ${error.message}`);
    this.events.emit(
      WHOIS_EVENTS.FAILED,
      new WhoisInformationFailedEvent(
        job.data.scannedDomainId,
        job.data.scanId,
        error.message,
      ),
    );
  }
}

/**
 * Re-park delay for a job whose registry is busy: the window's wait plus a random spread that
 * doubles per bounce (11 s, 22 s, 44 s, capped at 60 s), so a backlog on one registry fans out
 * instead of waking up together. The cap matters: a 5-minute cap left the registry idle at the
 * end of a backlog (load test: the last ~230 lookups took 45 min instead of ~5).
 */
export const BUSY_SPREAD_CAP_MS = 60_000;

export function busyDelayMs(
  retryAfterMs: number,
  bounces: number,
  random = Math.random,
): number {
  const spread = Math.min(
    11_000 * 2 ** Math.max(0, bounces - 1),
    BUSY_SPREAD_CAP_MS,
  );
  return retryAfterMs + Math.floor(random() * spread);
}
