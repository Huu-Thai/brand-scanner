import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import type { Job } from 'bullmq';
import { withJobContext } from '../../../common/utils/job-context.js';
import type { AnalyticsJobData } from '../../../queue/jobs.js';
import { QUEUES } from '../../../queue/queue.constants.js';
import { RuleEngineService } from '../../rules/rule-engine.service.js';
import { ScannedDomainsQuery } from '../../scanned-domains/scanned-domains.query.js';
import { WhoisInformationsQuery } from '../../whois-informations/whois-informations.query.js';
import { ScreenshotsQuery } from '../../screenshots/screenshots.query.js';
import { AnalyticsService } from '../analytics.service.js';

/** Scores one look-alike with all rules and appends the result. */
@Processor(QUEUES.ANALYTICS, { concurrency: 8 })
export class AnalyticsProcessor extends WorkerHost {
  private readonly logger = new Logger(AnalyticsProcessor.name);

  constructor(
    private readonly scannedDomains: ScannedDomainsQuery,
    private readonly whois: WhoisInformationsQuery,
    private readonly engine: RuleEngineService,
    private readonly analytics: AnalyticsService,
    private readonly screenshots: ScreenshotsQuery,
  ) {
    super();
  }

  process(job: Job<AnalyticsJobData>) {
    return withJobContext(job, job.data.scanId, async () => {
      const sd = await this.scannedDomains.getForEnrichment(
        job.data.scannedDomainId,
      );
      if (!sd) return { skipped: 'scanned domain gone' };
      const [whois, shot, reference] = await Promise.all([
        this.whois.latest(sd.id),
        this.screenshots.latestCaptured(sd.id),
        this.screenshots.reference(sd.originalDomainId),
      ]);
      const signals = (shot?.pageSignals ?? {}) as Partial<{
        hasPasswordField: boolean;
        formActionHosts: string[];
        text: string;
      }>;

      const result = await this.engine.score({
        originalDomain: sd.originalDomain.domain,
        fuzzerDomain: sd.domain,
        dns: {
          a: sd.dnsA ?? [],
          aaaa: sd.dnsAaaa ?? [],
          mx: sd.dnsMx ?? [],
          ns: sd.dnsNs ?? [],
          ttl: sd.dnsTtl,
        },
        whois: whois?.parseSucceeded
          ? { createdDate: whois.createdDate }
          : undefined,
        page: shot
          ? {
              perceptualHash: shot.perceptualHash,
              faviconHash: shot.faviconHash,
              title: shot.pageTitle,
              hasPasswordField: !!signals.hasPasswordField,
              formActionHosts: signals.formActionHosts ?? [],
              text: signals.text ?? '',
            }
          : undefined,
        reference:
          reference?.status === 'CAPTURED'
            ? {
                perceptualHash: reference.perceptualHash,
                faviconHash: reference.faviconHash,
              }
            : undefined,
      });

      const row = await this.analytics.record({
        scannedDomainId: sd.id,
        originalDomainId: sd.originalDomainId,
        domain: sd.domain,
        scanId: job.data.scanId,
        previousThreatLevel: sd.threatLevel,
        result,
      });
      this.logger.debug(
        `${sd.domain}: ${result.totalScore} → ${result.threatLevel} (${job.data.trigger})`,
      );
      return {
        analyticsId: row.id,
        totalScore: result.totalScore,
        threatLevel: result.threatLevel,
      };
    });
  }
}
