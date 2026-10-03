import { Processor, WorkerHost } from '@nestjs/bullmq';
import type { Job } from 'bullmq';
import { withJobContext } from '../../../common/utils/job-context.js';
import type { CtMatchJobData } from '../../../queue/jobs.js';
import { QUEUES } from '../../../queue/queue.constants.js';
import { DnsResolverService } from '../../dns-resolver/dns-resolver.service.js';
import { ScannedDomainsService } from '../../scanned-domains/scanned-domains.service.js';

/**
 * A certificate named a brand look-alike: resolve it, then track it like any discovered
 * look-alike (technique `ct:<kind>`) — WHOIS, screenshot, scoring and alerts follow via events.
 */
@Processor(QUEUES.CT_MATCHES, { concurrency: 4 })
export class CtMatchProcessor extends WorkerHost {
  constructor(
    private readonly dns: DnsResolverService,
    private readonly scannedDomains: ScannedDomainsService,
  ) {
    super();
  }

  process(job: Job<CtMatchJobData>) {
    return withJobContext(job, undefined, async () => {
      const { originalDomainId, domain, kind } = job.data;
      const resolution = await this.dns.resolve(domain);
      if (!resolution.registered) return { skipped: 'not registered (yet)' };
      const { inserted } = await this.scannedDomains.upsertBatch({
        originalDomainId,
        fuzzerByDomain: { [domain]: `ct:${kind}` },
        resolutions: [resolution],
      });
      return { tracked: domain, new: inserted > 0 };
    });
  }
}
