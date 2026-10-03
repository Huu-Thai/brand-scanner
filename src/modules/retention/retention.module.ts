import { type DynamicModule, Module } from '@nestjs/common';
import { QUEUES } from '../../queue/queue.constants.js';
import { RetentionProcessor } from './processors/retention.processor.js';
import { RetentionController } from './retention.controller.js';
import { RetentionLock } from './retention.lock.js';
import { RetentionScheduler } from './retention.scheduler.js';
import { RetentionService } from './retention.service.js';

/** API side: admin endpoints. */
@Module({
  controllers: [RetentionController],
  providers: [RetentionService, RetentionLock],
  exports: [RetentionService],
})
export class RetentionModule {}

/** Worker side: processor + schedulers, only where the `retention` queue is served. */
@Module({})
export class RetentionWorkerModule {
  static forQueues(queues: readonly string[]): DynamicModule {
    const serve = queues.length === 0 || queues.includes(QUEUES.RETENTION);
    return {
      module: RetentionWorkerModule,
      providers: serve
        ? [
            RetentionService,
            RetentionLock,
            RetentionProcessor,
            RetentionScheduler,
          ]
        : [],
    };
  }
}
