import { WorkerHost } from '@nestjs/bullmq';
import { Injectable, type OnApplicationBootstrap } from '@nestjs/common';
import { DiscoveryService } from '@nestjs/core';
import type { Job, Worker } from 'bullmq';
import { jobDuration, jobsTotal } from './metrics.js';

/** Attaches job metrics to every BullMQ worker in this process — no per-processor code needed. */
@Injectable()
export class JobMetricsBinder implements OnApplicationBootstrap {
  constructor(private readonly discovery: DiscoveryService) {}

  onApplicationBootstrap(): void {
    for (const wrapper of this.discovery.getProviders()) {
      const host = wrapper.instance as unknown;
      if (!(host instanceof WorkerHost)) continue;
      let worker: Worker;
      try {
        worker = host.worker;
      } catch {
        continue; // not started (e.g. autorun disabled)
      }
      const queue = worker.name;
      const record = (job: Job | undefined, status: 'completed' | 'failed') => {
        jobsTotal.inc({ queue, status });
        if (job?.processedOn && job.finishedOn)
          jobDuration.observe(
            { queue, status },
            (job.finishedOn - job.processedOn) / 1000,
          );
      };
      worker.on('completed', (job: Job) => record(job, 'completed'));
      worker.on('failed', (job: Job | undefined) => record(job, 'failed'));
    }
  }
}
