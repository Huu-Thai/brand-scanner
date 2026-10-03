import { randomUUID } from 'node:crypto';
import {
  Inject,
  Injectable,
  type LoggerService,
  NestMiddleware,
} from '@nestjs/common';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import type { NextFunction, Request, Response } from 'express';
import { requestContext } from '../../logger/request-context.js';
import { REQUEST_ID_HEADER } from '../constants/api.constants.js';

const VALID_ID = /^[A-Za-z0-9-]{8,64}$/;

/**
 * Establishes the per-request logging context (x-request-id, propagated or generated)
 * and writes one access-log line per request once the response finishes.
 */
@Injectable()
export class RequestContextMiddleware implements NestMiddleware {
  constructor(
    @Inject(WINSTON_MODULE_NEST_PROVIDER)
    private readonly logger: LoggerService,
  ) {}

  use(req: Request, res: Response, next: NextFunction): void {
    const incoming = req.header(REQUEST_ID_HEADER);
    const requestId =
      incoming && VALID_ID.test(incoming) ? incoming : randomUUID();
    res.setHeader(REQUEST_ID_HEADER, requestId);
    const started = process.hrtime.bigint();

    requestContext.run({ requestId }, () => {
      res.on('finish', () => {
        const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
        const entry = {
          message: `${req.method} ${req.originalUrl.split('?')[0]} ${res.statusCode}`,
          method: req.method,
          path: req.originalUrl.split('?')[0],
          statusCode: res.statusCode,
          durationMs: Math.round(durationMs * 10) / 10,
          requestId,
          context: 'HTTP',
        };
        if (res.statusCode >= 500) this.logger.error?.(entry);
        else if (res.statusCode >= 400) this.logger.warn?.(entry);
        else this.logger.log(entry);
      });
      next();
    });
  }
}
