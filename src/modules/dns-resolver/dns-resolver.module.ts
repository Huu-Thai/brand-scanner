import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../config/configuration.js';
import { DnsResolverService } from './dns-resolver.service.js';

@Module({
  providers: [
    {
      provide: DnsResolverService,
      inject: [ConfigService],
      useFactory: (config: ConfigService<AppConfig, true>) =>
        new DnsResolverService(config),
    },
  ],
  exports: [DnsResolverService],
})
export class DnsResolverModule {}
