import { EventEmitter } from 'node:events';
import type { LoggerService } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { requestContext } from '../../logger/request-context.js';
import { RequestContextMiddleware } from './request-context.middleware.js';

function run(headerId: string | undefined, statusCode = 200) {
  const logger = {
    log: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  } as unknown as LoggerService;
  const res = Object.assign(new EventEmitter(), {
    statusCode,
    setHeader: vi.fn(),
  });
  const req = {
    method: 'GET',
    originalUrl: '/api/v1/health?verbose=1',
    header: () => headerId,
  } as unknown as Request;
  let seen: string | undefined;
  const next: NextFunction = () => {
    seen = requestContext.get()?.requestId;
  };
  new RequestContextMiddleware(logger).use(
    req,
    res as unknown as Response,
    next,
  );
  res.emit('finish');
  return { logger, res, seen };
}

describe('RequestContextMiddleware', () => {
  it('propagates a valid incoming x-request-id', () => {
    const { res, seen } = run('trace-abc-123');
    expect(seen).toBe('trace-abc-123');
    expect(res.setHeader).toHaveBeenCalledWith('x-request-id', 'trace-abc-123');
  });

  it('generates an id when the incoming one is missing or unsafe', () => {
    expect(run(undefined).seen).toMatch(/^[0-9a-f-]{36}$/);
    expect(run('bad id\nwith newline').seen).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('writes one access-log line without the query string, levelled by status', () => {
    const ok = run('trace-abc-123', 200).logger;
    expect(ok.log).toHaveBeenCalledWith(
      expect.objectContaining({
        path: '/api/v1/health',
        statusCode: 200,
        context: 'HTTP',
      }),
    );
    expect(run('trace-abc-123', 404).logger.warn).toHaveBeenCalled();
    expect(run('trace-abc-123', 503).logger.error).toHaveBeenCalled();
  });
});
