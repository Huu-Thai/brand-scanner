import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type {
  ApiPrincipal,
  AuthenticatedRequest,
} from '../guards/api-key.guard.js';

/** The authenticated API-key principal (name + scope). */
export const Principal = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): ApiPrincipal | undefined =>
    ctx.switchToHttp().getRequest<AuthenticatedRequest>().principal,
);
