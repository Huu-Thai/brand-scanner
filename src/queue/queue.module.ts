import { BullModule } from '@nestjs/bullmq';
import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/configuration.js';
import { buildRedisOptions } from '../redis/redis.options.js';
import { SCAN_FLOW_PRODUCER } from './jobs.js';
import { ALL_QUEUES } from './queue.constants.js';

@Global()
@Module({
  imports: [
    BullModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<AppConfig, true>) => ({
        connection: buildRedisOptions(
          config.get('redis', { infer: true }),
          'queue',
        ),
        prefix: 'bull',
        defaultJobOptions: {
          attempts: 3,
          backoff: { type: 'exponential', delay: 5_000 },
          removeOnComplete: { age: 86_400, count: 5_000 },
          removeOnFail: { age: 7 * 86_400 },
        },
      }),
    }),
    BullModule.registerQueue(...ALL_QUEUES.map((name) => ({ name }))),
    BullModule.registerFlowProducer({ name: SCAN_FLOW_PRODUCER }),
  ],
  exports: [BullModule],
})
export class QueueModule {}
