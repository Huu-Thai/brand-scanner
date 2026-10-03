import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { WinstonModule } from 'nest-winston';
import type { AppConfig } from '../config/configuration.js';
import { buildWinstonOptions } from './winston.config.js';

@Global()
@Module({
  imports: [
    WinstonModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<AppConfig, true>) =>
        buildWinstonOptions({
          env: config.get('env', { infer: true }),
          log: config.get('log', { infer: true }),
        }),
    }),
  ],
  exports: [WinstonModule],
})
export class LoggerModule {}
