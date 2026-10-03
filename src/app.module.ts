import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { ThrottlerModule } from '@nestjs/throttler';
import { EventsModule } from './common/events/events.module.js';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter.js';
import { ApiKeyGuard } from './common/guards/api-key.guard.js';
import { RequestContextMiddleware } from './common/middleware/request-context.middleware.js';
import { AppConfigModule } from './config/config.module.js';
import type { AppConfig } from './config/configuration.js';
import { PrismaModule } from './database/prisma.module.js';
import { UserIdentityService } from './common/auth/user-identity.service.js';
import { ApiKeyThrottlerGuard } from './common/guards/api-key-throttler.guard.js';
import { MetricsController } from './metrics/metrics.controller.js';
import { HttpMetricsMiddleware } from './metrics/http-metrics.middleware.js';
import { MetricsModule } from './metrics/metrics.module.js';
import { HealthModule } from './health/health.module.js';
import { LoggerModule } from './logger/logger.module.js';
import { QueueModule } from './queue/queue.module.js';
import { RedisModule } from './redis/redis.module.js';
import { StorageModule } from './storage/storage.module.js';
import { SystemController } from './system/system.controller.js';
import { OriginalDomainsModule } from './modules/original-domains/original-domains.module.js';
import { ScannedDomainsModule } from './modules/scanned-domains/scanned-domains.module.js';
import { ScansApiModule } from './modules/scans/scans-api.module.js';
import { AnalyticsModule } from './modules/analytics/analytics.module.js';
import { RulesModule } from './modules/rules/rules.module.js';
import { ScreenshotsModule } from './modules/screenshots/screenshots.module.js';
import { CtMonitorModule } from './modules/ct-monitor/ct-monitor.module.js';
import { InsightsModule } from './modules/insights/insights.module.js';
import { AlertsModule } from './modules/alerts/alerts.module.js';
import { RetentionModule } from './modules/retention/retention.module.js';
import { ReviewsModule } from './modules/reviews/reviews.module.js';
import { ThreatFeedSyncModule } from './modules/threat-feed-sync/threat-feed-sync.module.js';
import { WhoisInformationsModule } from './modules/whois-informations/whois-informations.module.js';

/** Infrastructure shared by the API and the worker processes. */
export const CORE_IMPORTS = [
  AppConfigModule,
  LoggerModule,
  PrismaModule,
  RedisModule,
  QueueModule,
  StorageModule,
  EventsModule,
  MetricsModule,
];

@Module({
  imports: [
    ...CORE_IMPORTS,
    ThrottlerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<AppConfig, true>) => {
        const { ttlMs, limit } = config.get('throttle', { infer: true });
        return [{ ttl: ttlMs, limit }];
      },
    }),
    HealthModule,
    OriginalDomainsModule,
    ScansApiModule,
    ScannedDomainsModule,
    WhoisInformationsModule,
    ScreenshotsModule,
    RulesModule,
    AnalyticsModule,
    ReviewsModule,
    ThreatFeedSyncModule,
    RetentionModule,
    AlertsModule,
    CtMonitorModule,
    InsightsModule,
  ],
  controllers: [SystemController, MetricsController],
  providers: [
    // Order matters: authenticate first, then rate-limit.
    UserIdentityService,
    { provide: APP_GUARD, useClass: ApiKeyGuard },
    { provide: APP_GUARD, useClass: ApiKeyThrottlerGuard },
    { provide: APP_FILTER, useClass: AllExceptionsFilter },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer
      .apply(RequestContextMiddleware, HttpMetricsMiddleware)
      .forRoutes('*path');
  }
}
