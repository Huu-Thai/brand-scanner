import type { Job } from 'bullmq';
import { requestContext } from '../../logger/request-context.js';

/** Runs a processor body with jobId / queue / scanId on every log line it produces. */
export function withJobContext<T>(
  job: Job,
  scanId: string | undefined,
  fn: () => Promise<T>,
): Promise<T> {
  return requestContext.run(
    { jobId: job.id, queue: job.queueName, scanId },
    fn,
  );
}
