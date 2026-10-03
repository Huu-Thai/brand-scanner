import { Global, Module } from '@nestjs/common';
import { S3StorageService } from './s3-storage.service.js';
import { StorageService } from './storage.service.js';

@Global()
@Module({
  providers: [{ provide: StorageService, useClass: S3StorageService }],
  exports: [StorageService],
})
export class StorageModule {}
