import { SetMetadata } from '@nestjs/common';
import type { ApiKeyScope } from '../../config/configuration.js';

export const IS_PUBLIC_KEY = 'auth:isPublic';
export const REQUIRED_SCOPE_KEY = 'auth:requiredScope';

/** Skips API-key authentication (health checks only). */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

/**
 * Overrides the default scope (GET/HEAD → read, everything else → write),
 * e.g. `@RequireScope('admin')` on retention or queue-admin endpoints.
 */
export const RequireScope = (scope: ApiKeyScope) =>
  SetMetadata(REQUIRED_SCOPE_KEY, scope);
