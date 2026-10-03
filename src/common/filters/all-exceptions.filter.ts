import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Inject,
  type LoggerService,
} from '@nestjs/common';
import { STATUS_CODES } from 'node:http';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import type { Request, Response } from 'express';
import {
  constraintFromMeta,
  FOREIGN_KEYS,
  UNIQUE_CONSTRAINTS,
} from '../../database/constraints.js';
import { Prisma } from '../../database/generated/prisma/client.js';
import { requestContext } from '../../logger/request-context.js';

export interface ErrorBody {
  statusCode: number;
  message: string | string[];
  error: string;
  path: string;
  timestamp: string;
  requestId?: string;
}

export function fromPrismaError(error: Prisma.PrismaClientKnownRequestError): {
  status: number;
  message: string;
} {
  const constraint = constraintFromMeta(error.meta);
  switch (error.code) {
    case 'P2002':
      return {
        status: HttpStatus.CONFLICT,
        message:
          (constraint && UNIQUE_CONSTRAINTS[constraint]) ??
          'A record with the same unique value already exists',
      };
    case 'P2003':
      return {
        status: HttpStatus.BAD_REQUEST,
        message:
          (constraint && FOREIGN_KEYS[constraint]) ??
          'A referenced record does not exist',
      };
    case 'P2025':
      return { status: HttpStatus.NOT_FOUND, message: 'Record not found' };
    default:
      return {
        status: HttpStatus.INTERNAL_SERVER_ERROR,
        message: 'Internal server error',
      };
  }
}

/**
 * Uniform error body for every failure. Known Prisma errors map to 4xx with
 * safe messages; unexpected errors are logged with stack and returned as a
 * generic 500 (no internals leak to clients).
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  constructor(
    @Inject(WINSTON_MODULE_NEST_PROVIDER)
    private readonly logger: LoggerService,
  ) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message: string | string[] = 'Internal server error';

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const res = exception.getResponse();
      message =
        typeof res === 'object' && res !== null && 'message' in res
          ? (res as { message: string | string[] }).message
          : exception.message;
    } else if (exception instanceof Prisma.PrismaClientKnownRequestError) {
      ({ status, message } = fromPrismaError(exception));
    }

    if (status >= 500) {
      this.logger.error(
        `Unhandled error on ${request.method} ${request.originalUrl}`,
        exception instanceof Error ? exception.stack : String(exception),
        AllExceptionsFilter.name,
      );
    }

    const body: ErrorBody = {
      statusCode: status,
      message,
      error: STATUS_CODES[status] ?? 'Error',
      path: request.originalUrl.split('?')[0],
      timestamp: new Date().toISOString(),
      requestId: requestContext.get()?.requestId,
    };
    response.status(status).json(body);
  }
}
