import { Module } from '@nestjs/common';
import { ScanScheduleReconciler } from './scan-schedule.reconciler.js';
import { ScansModule } from './scans.module.js';

/** Imported by the API process only. */
@Module({
  imports: [ScansModule],
  providers: [ScanScheduleReconciler],
})
export class ScansApiModule {}
