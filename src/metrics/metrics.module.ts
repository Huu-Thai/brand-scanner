import { Global, Module } from '@nestjs/common';
import { DiscoveryModule } from '@nestjs/core';
import { EventMetricsListener } from './event-metrics.listener.js';
import { JobMetricsBinder } from './job-metrics.binder.js';
import { MetricsCollector } from './metrics.collector.js';
import { WorkerMetricsServer } from './worker-metrics.server.js';

@Global()
@Module({
  imports: [DiscoveryModule],
  providers: [
    MetricsCollector,
    JobMetricsBinder,
    EventMetricsListener,
    WorkerMetricsServer,
  ],
  exports: [MetricsCollector],
})
export class MetricsModule {}
