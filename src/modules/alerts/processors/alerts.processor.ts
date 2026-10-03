import { Processor, WorkerHost } from '@nestjs/bullmq';
import { UnrecoverableError, type Job } from 'bullmq';
import { withJobContext } from '../../../common/utils/job-context.js';
import { JOBS, type AlertJobData } from '../../../queue/jobs.js';
import { QUEUES } from '../../../queue/queue.constants.js';
import { AlertsService } from '../alerts.service.js';
import { PermanentDeliveryError } from '../senders/alert-sender.js';

@Processor(QUEUES.ALERTS, { concurrency: 8 })
export class AlertsProcessor extends WorkerHost {
  constructor(private readonly alerts: AlertsService) {
    super();
  }

  process(job: Job<AlertJobData>) {
    return withJobContext(job, undefined, async () => {
      if (job.name === JOBS.SEND_DIGEST) return this.alerts.sendDigests();
      const final = job.attemptsMade + 1 >= (job.opts.attempts ?? 1);
      try {
        return {
          result: await this.alerts.deliver(job.data.deliveryId!, final),
        };
      } catch (e) {
        if (e instanceof PermanentDeliveryError)
          throw new UnrecoverableError(e.message);
        throw e;
      }
    });
  }
}
