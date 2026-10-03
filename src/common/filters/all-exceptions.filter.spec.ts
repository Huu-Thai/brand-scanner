import {
  BadRequestException,
  type ArgumentsHost,
  type LoggerService,
} from '@nestjs/common';
import { Prisma } from '../../database/generated/prisma/client.js';
import { requestContext } from '../../logger/request-context.js';
import {
  AllExceptionsFilter,
  fromPrismaError,
} from './all-exceptions.filter.js';

function prismaError(code: string, index?: string) {
  return new Prisma.PrismaClientKnownRequestError('db error', {
    code,
    clientVersion: '7.10.0',
    // Real Prisma 7 + adapter-pg shape (captured from a live FK violation).
    meta: index
      ? { driverAdapterError: { cause: { constraint: { index } } } }
      : {},
  });
}

function host() {
  const json = vi.fn();
  const status = vi.fn(() => ({ json }));
  const h = {
    switchToHttp: () => ({
      getResponse: () => ({ status }),
      getRequest: () => ({ method: 'POST', originalUrl: '/api/v1/scans?x=1' }),
    }),
  } as unknown as ArgumentsHost;
  return { h, status, json };
}

describe('fromPrismaError', () => {
  it('maps FK violations to 400 with a constraint-specific message', () => {
    expect(
      fromPrismaError(prismaError('P2003', 'fk_reviews_scanned_domain_id')),
    ).toEqual({
      status: 400,
      message: 'Scanned domain does not exist',
    });
    expect(fromPrismaError(prismaError('P2003', 'fk_unknown')).message).toBe(
      'A referenced record does not exist',
    );
  });

  it('maps unique violations to 409', () => {
    expect(
      fromPrismaError(prismaError('P2002', 'uq_original_domains_domain')),
    ).toEqual({
      status: 409,
      message: 'This original domain is already registered',
    });
  });

  it('maps record-not-found to 404 and anything else to 500', () => {
    expect(fromPrismaError(prismaError('P2025')).status).toBe(404);
    expect(fromPrismaError(prismaError('P1001')).status).toBe(500);
  });
});

describe('AllExceptionsFilter', () => {
  const logger = {
    error: vi.fn(),
    log: vi.fn(),
    warn: vi.fn(),
  } as unknown as LoggerService;
  const filter = new AllExceptionsFilter(logger);

  it('returns the uniform body for HTTP exceptions with the request id', () => {
    const { h, status, json } = host();
    requestContext.run({ requestId: 'req-12345678' }, () =>
      filter.catch(new BadRequestException(['domain must be a valid FQDN']), h),
    );
    expect(status).toHaveBeenCalledWith(400);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: 400,
        message: ['domain must be a valid FQDN'],
        error: 'Bad Request',
        path: '/api/v1/scans',
        requestId: 'req-12345678',
      }),
    );
  });

  it('hides internals of unexpected errors and logs them', () => {
    const { h, status, json } = host();
    filter.catch(new Error('connection string postgres://u:p@db leaked?'), h);
    expect(status).toHaveBeenCalledWith(500);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'Internal server error' }),
    );
    expect(logger.error).toHaveBeenCalled();
  });

  it('maps Prisma errors through fromPrismaError', () => {
    const { h, status } = host();
    filter.catch(prismaError('P2003', 'fk_scans_original_domain_id'), h);
    expect(status).toHaveBeenCalledWith(400);
  });
});
