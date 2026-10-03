import {
  InjectFlowProducer,
  OnWorkerEvent,
  Processor,
  WorkerHost,
} from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { FlowProducer, Job } from 'bullmq';
import { chunk } from '../../../common/utils/concurrency.js';
import { withJobContext } from '../../../common/utils/job-context.js';
import type { AppConfig } from '../../../config/configuration.js';
import { ScanStatus } from '../../../database/generated/prisma/enums.js';
import {
  type FinalizeJobData,
  JOBS,
  jobIds,
  type OrchestrateJobData,
  type ResolveJobData,
  SCAN_FLOW_PRODUCER,
} from '../../../queue/jobs.js';
import { QUEUES } from '../../../queue/queue.constants.js';
import type { FuzzerName } from '../../fuzzer/fuzzer.constants.js';
import { FuzzerService } from '../../fuzzer/fuzzer.service.js';
import { ScannedDomainsQuery } from '../../scanned-domains/scanned-domains.query.js';
import { OriginalDomainsQuery } from '../../original-domains/original-domains.query.js';
import type { ScanOptions } from '../events/scan.events.js';
import { ScansService } from '../scans.service.js';

/**
 * QUEUED → FUZZING → RESOLVING. Generates permutations and fans them out as one BullMQ flow:
 * parent `finalize` + one `resolve` child per batch. Job ids are deterministic, so a retried
 * orchestrator re-adding the flow is a no-op rather than a duplicate scan.
 */
@Processor(QUEUES.SCAN_ORCHESTRATOR, { concurrency: 2 })
export class ScanOrchestratorProcessor extends WorkerHost {
  private readonly logger = new Logger(ScanOrchestratorProcessor.name);
  private readonly batchSize: number;
  private readonly maxPermutations: number;

  constructor(
    private readonly scans: ScansService,
    private readonly fuzzer: FuzzerService,
    private readonly originalDomains: OriginalDomainsQuery,
    private readonly scannedDomains: ScannedDomainsQuery,
    @InjectFlowProducer(SCAN_FLOW_PRODUCER) private readonly flow: FlowProducer,
    config: ConfigService<AppConfig, true>,
  ) {
    super();
    ({ batchSize: this.batchSize, maxPermutations: this.maxPermutations } =
      config.get('scan', { infer: true }));
  }

  process(
    job: Job<OrchestrateJobData>,
  ): Promise<{ permutations: number; batches: number } | { skipped: string }> {
    return withJobContext(job, job.data.scanId, () =>
      this.run(job.data.scanId),
    );
  }

  private async run(scanId: string) {
    let scan = await this.scans.get(scanId);
    if (scan.status === ScanStatus.QUEUED)
      scan = (await this.scans.startFuzzing(scanId)) ?? scan;
    if (
      scan.status !== ScanStatus.FUZZING &&
      scan.status !== ScanStatus.RESOLVING
    ) {
      return { skipped: `scan is ${scan.status}` }; // cancelled / failed / already finished
    }

    const original = await this.originalDomains.getScannable(
      scan.originalDomainId,
    );
    const options = (scan.options ?? {}) as ScanOptions;
    const started = Date.now();
    const permutations = this.fuzzer.generate(original.domain, {
      fuzzers: options.fuzzers as FuzzerName[],
    });
    this.logger.log(
      `Generated ${permutations.length} permutations for ${original.domain} in ${Date.now() - started}ms`,
    );

    if (permutations.length > this.maxPermutations) {
      await this.scans.fail(
        scanId,
        `${permutations.length} permutations exceed SCAN_MAX_PERMUTATIONS (${this.maxPermutations}); narrow options.fuzzers`,
      );
      return { skipped: 'too many permutations' };
    }
    if (permutations.length === 0) {
      await this.scans.complete(scanId, {
        registeredCount: 0,
        newCount: 0,
        failedCount: 0,
      });
      return { permutations: 0, batches: 0 };
    }

    const pairs = permutations.map((p): [string, string] => [
      p.domain,
      p.fuzzer,
    ]);
    // Full scans also re-resolve look-alikes found by CT monitoring (the fuzzer never generates
    // them), so their liveness is tracked — and they are marked INACTIVE — like everything else.
    if (!options.fuzzers?.length) {
      const seen = new Set(pairs.map(([d]) => d));
      for (const pair of await this.scannedDomains.ctDomains(original.id))
        if (!seen.has(pair[0])) pairs.push(pair);
    }
    if (scan.status === ScanStatus.FUZZING)
      await this.scans.startResolving(scanId, pairs.length);
    const batches = chunk(pairs, this.batchSize);
    await this.flow.add({
      name: JOBS.FINALIZE,
      queueName: QUEUES.SCAN_FINALIZE,
      data: {
        scanId,
        batchSize: this.batchSize,
        permutationsTotal: pairs.length,
      } satisfies FinalizeJobData,
      opts: { jobId: jobIds.finalize(scanId), attempts: 3 },
      children: batches.map((batch, batchIndex) => ({
        name: JOBS.RESOLVE,
        queueName: QUEUES.DNS_RESOLVE,
        data: {
          scanId,
          originalDomainId: original.id,
          batchIndex,
          permutations: batch,
        } satisfies ResolveJobData,
        opts: {
          jobId: jobIds.resolve(scanId, batchIndex),
          attempts: 3,
          backoff: { type: 'exponential', delay: 10_000 },
          // A batch that still fails after retries must not block the scan: the parent
          // proceeds and counts it via getIgnoredChildrenFailures().
          ignoreDependencyOnFailure: true,
        },
      })),
    });
    return { permutations: permutations.length, batches: batches.length };
  }

  @OnWorkerEvent('failed')
  async onFailed(job: Job<OrchestrateJobData>, error: Error): Promise<void> {
    if (job.attemptsMade < (job.opts.attempts ?? 1)) return;
    this.logger.error(
      `Orchestration failed for scan ${job.data.scanId}: ${error.message}`,
    );
    await this.scans
      .fail(job.data.scanId, `Orchestration failed: ${error.message}`)
      .catch(() => undefined);
  }
}
