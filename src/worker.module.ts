import { type DynamicModule, Logger, Module } from '@nestjs/common';
import { CORE_IMPORTS } from './app.module.js';
import { ALL_QUEUES } from './queue/queue.constants.js';
import { EnrichmentWorkerModule } from './modules/enrichment-worker.module.js';
import { CtMonitorWorkerModule } from './modules/ct-monitor/ct-monitor.module.js';
import { AlertsWorkerModule } from './modules/alerts/alerts.module.js';
import { RetentionWorkerModule } from './modules/retention/retention.module.js';
import { ScansWorkerModule } from './modules/scans/scans-worker.module.js';

/**
 * Worker process root. WORKER_QUEUES (comma separated; empty = all) selects which
 * processors this process runs, so each deployment scales one queue group independently.
 */
@Module({})
export class WorkerModule {
  static forQueues(queues: string[]): DynamicModule {
    const unknown = queues.filter((q) => !(ALL_QUEUES as string[]).includes(q));
    if (unknown.length) {
      throw new Error(
        `WORKER_QUEUES contains unknown queues: ${unknown.join(', ')} (known: ${ALL_QUEUES.join(', ')})`,
      );
    }
    new Logger('WorkerModule').log(
      `Processors: ${queues.length ? queues.join(', ') : 'all queues'}`,
    );
    return {
      module: WorkerModule,
      imports: [
        ...CORE_IMPORTS,
        ScansWorkerModule.forQueues(queues),
        EnrichmentWorkerModule.forQueues(queues),
        RetentionWorkerModule.forQueues(queues),
        AlertsWorkerModule.forQueues(queues),
        CtMonitorWorkerModule.forQueues(queues),
      ],
    };
  }
}
