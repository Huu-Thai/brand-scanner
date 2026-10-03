import { Module } from '@nestjs/common';
import { FuzzerService } from './fuzzer.service.js';

@Module({
  providers: [FuzzerService],
  exports: [FuzzerService],
})
export class FuzzerModule {}
