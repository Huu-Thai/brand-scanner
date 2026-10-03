import { type DynamicModule, Module } from '@nestjs/common';
import { QUEUES } from '../../queue/queue.constants.js';
import { ScannedDomainsModule } from '../scanned-domains/scanned-domains.module.js';
import { AlertChannelsService } from './alert-channels.service.js';
import { AlertCrypto } from './alert-crypto.js';
import { AlertTargetGuard } from './alert-target.guard.js';
import { AlertSubscriptionsService } from './alert-subscriptions.service.js';
import { AlertsController } from './alerts.controller.js';
import { AlertsEnqueuer } from './alerts.enqueuer.js';
import { AlertsScheduler } from './alerts.scheduler.js';
import { AlertsService } from './alerts.service.js';
import { AlertTriggerListener } from './listeners/alert-trigger.listener.js';
import { AlertsProcessor } from './processors/alerts.processor.js';
import { AlertSender } from './senders/alert-sender.js';

const CORE = [
  AlertCrypto,
  AlertTargetGuard,
  AlertSender,
  AlertChannelsService,
  AlertSubscriptionsService,
  AlertsService,
  AlertsEnqueuer,
  AlertTriggerListener,
];

/** Alerting (PLAN §14 #6). Listeners run in every process (events are emitted in API and worker). */
@Module({
  imports: [ScannedDomainsModule],
  controllers: [AlertsController],
  providers: CORE,
  exports: [AlertsService],
})
export class AlertsModule {}

/** Worker side: delivery processor + digest scheduler, where the `alerts` queue is served. */
@Module({})
export class AlertsWorkerModule {
  static forQueues(queues: readonly string[]): DynamicModule {
    const serve = queues.length === 0 || queues.includes(QUEUES.ALERTS);
    return {
      module: AlertsWorkerModule,
      imports: [ScannedDomainsModule],
      providers: [
        ...CORE,
        ...(serve ? [AlertsProcessor, AlertsScheduler] : []),
      ],
    };
  }
}
