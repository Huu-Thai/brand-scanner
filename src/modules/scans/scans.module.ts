import { Module } from '@nestjs/common';
import { OriginalDomainsModule } from '../original-domains/original-domains.module.js';
import { ScanLifecycleListener } from './listeners/scan-lifecycle.listener.js';
import { ScanScheduleService } from './scan-schedule.service.js';
import { ScansController } from './scans.controller.js';
import { ScansService } from './scans.service.js';

@Module({
  imports: [OriginalDomainsModule],
  controllers: [ScansController],
  providers: [ScansService, ScanScheduleService, ScanLifecycleListener],
  exports: [ScansService, ScanScheduleService],
})
export class ScansModule {}
