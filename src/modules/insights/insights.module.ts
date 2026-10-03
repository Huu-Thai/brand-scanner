import { Module } from '@nestjs/common';
import { InsightsController } from './insights.controller.js';
import { InsightsService } from './insights.service.js';

/** Read-only investigation views (graph, timeline) for the console. */
@Module({ controllers: [InsightsController], providers: [InsightsService] })
export class InsightsModule {}
