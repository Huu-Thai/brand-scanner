import { DomainStatus } from '../../database/generated/prisma/enums.js';

/** Who is changing a look-alike's status. */
export type StatusChangeSource = 'system' | 'manual' | 'review';

/** Statuses the scan pipeline owns. Analyst decisions are never overwritten by it. */
export const SYSTEM_STATUSES: DomainStatus[] = [
  DomainStatus.NEW,
  DomainStatus.ACTIVE,
  DomainStatus.PARKED,
  DomainStatus.INACTIVE,
];

/** Statuses an analyst may set directly (PATCH / bulk). */
export const MANUAL_TARGETS: DomainStatus[] = [
  DomainStatus.UNDER_REVIEW,
  DomainStatus.CONFIRMED_THREAT,
  DomainStatus.FALSE_POSITIVE,
  DomainStatus.TAKEN_DOWN,
  DomainStatus.ALLOWLISTED,
  DomainStatus.ACTIVE, // "reopen" an analyst decision
];

/**
 * Returns why `from → to` is not allowed for `source`, or null when it is.
 *   system : only between system statuses (scans can't undo an analyst's call)
 *   manual : only to analyst targets; TAKEN_DOWN only after CONFIRMED_THREAT
 *   review : always allowed (a review is the authoritative record of a decision)
 */
export function transitionError(
  from: DomainStatus,
  to: DomainStatus,
  source: StatusChangeSource,
): string | null {
  if (from === to) return null;
  if (source === 'review') return null;
  if (source === 'system') {
    return SYSTEM_STATUSES.includes(from) && SYSTEM_STATUSES.includes(to)
      ? null
      : `${from} is an analyst decision; scans cannot change it`;
  }
  if (!MANUAL_TARGETS.includes(to))
    return `${to} is set by scans, not manually`;
  if (
    to === DomainStatus.TAKEN_DOWN &&
    from !== DomainStatus.CONFIRMED_THREAT
  ) {
    return 'Only a CONFIRMED_THREAT can be marked TAKEN_DOWN';
  }
  if (to === DomainStatus.ACTIVE && SYSTEM_STATUSES.includes(from)) {
    return 'ACTIVE can only be set to reopen an analyst decision';
  }
  return null;
}
