import { Processor, WorkerHost } from '@nestjs/bullmq';
import type { Job } from 'bullmq';
import { withJobContext } from '../../../common/utils/job-context.js';
import type { RescanJobData } from '../../../queue/jobs.js';
import { QUEUES } from '../../../queue/queue.constants.js';
import { DnsResolverService } from '../../dns-resolver/dns-resolver.service.js';
import { ScannedDomainsService } from '../scanned-domains.service.js';

/** Re-resolves one look-alike; the resulting `updated(force)` event re-runs WHOIS, screenshot and scoring. */
@Processor(QUEUES.DOMAIN_RESCAN, { concurrency: 4 })
export class DomainRescanProcessor extends WorkerHost {
  constructor(
    private readonly dns: DnsResolverService,
    private readonly service: ScannedDomainsService,
  ) {
    super();
  }

  process(job: Job<RescanJobData>) {
    return withJobContext(job, undefined, async () => {
      const resolution = await this.dns.resolve(job.data.domain);
      const outcome = await this.service.refreshDns(
        job.data.scannedDomainId,
        resolution,
        job.data.actor,
      );
      return { outcome, registered: resolution.registered };
    });
  }
}
