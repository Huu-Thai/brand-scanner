import { Injectable, type NestMiddleware } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { httpDuration } from './metrics.js';

/** Request latency by *route template* (`/api/v1/scanned-domains/:id`), never raw paths (cardinality). */
@Injectable()
export class HttpMetricsMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction): void {
    const start = process.hrtime.bigint();
    res.on('finish', () => {
      const template = req.route?.path
        ? `${req.baseUrl ?? ''}${String(req.route.path)}`
        : 'unmatched';
      if (template.endsWith('/metrics')) return;
      httpDuration.observe(
        { method: req.method, route: template, status: String(res.statusCode) },
        Number(process.hrtime.bigint() - start) / 1e9,
      );
    });
    next();
  }
}
