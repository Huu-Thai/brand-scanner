import { Module } from '@nestjs/common';
import { ScannedDomainsModule } from '../scanned-domains/scanned-domains.module.js';
import { ReviewsController } from './reviews.controller.js';
import { ReviewsService } from './reviews.service.js';

@Module({
  imports: [ScannedDomainsModule],
  controllers: [ReviewsController],
  providers: [ReviewsService],
})
export class ReviewsModule {}
