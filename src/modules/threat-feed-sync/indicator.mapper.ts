import {
  DomainStatus,
  ThreatLevel,
} from '../../database/generated/prisma/enums.js';
import type { NewIndicator } from '../../integrations/threat-feed/threat-feed.client.js';

export type PushAction = 'upsert' | 'deactivate';

/** Statuses whose look-alike must be published as an active indicator. */
export const PUBLISHED_STATUSES: readonly DomainStatus[] = [
  DomainStatus.CONFIRMED_THREAT,
];

/**
 * What a status transition means for the indicator, or null when nothing changes. Leaving the
 * published set (false positive, allowlisted, taken down, …) retires the indicator; threat-feed
 * keeps it, inactive, as history.
 */
export function pushActionFor(
  from: DomainStatus,
  to: DomainStatus,
): PushAction | null {
  if (PUBLISHED_STATUSES.includes(to)) return 'upsert';
  if (PUBLISHED_STATUSES.includes(from)) return 'deactivate';
  return null;
}

/** An analyst confirmed it, so severity is at least "high"; a high automated score makes it critical. */
export function severityFor(threatLevel: ThreatLevel): string {
  return threatLevel === ThreatLevel.HIGH_RISK ? 'critical' : 'high';
}

const tagSafe = (v: string) =>
  v
    .toLowerCase()
    .replace(/[^a-z0-9.-]+/g, '-')
    .slice(0, 60);

export function indicatorFor(
  row: {
    domain: string;
    fuzzer: string;
    threatLevel: ThreatLevel;
    originalDomain: { domain: string };
  },
  sourceId: string,
): NewIndicator {
  return {
    value: row.domain.toLowerCase(),
    type: 'DOMAIN',
    sourceId,
    severity: severityFor(row.threatLevel),
    confidence: 95,
    isActive: true,
    tags: [
      'typosquat',
      'source:fuzzer-scanner',
      `fuzzer:${tagSafe(row.fuzzer)}`,
      `brand:${tagSafe(row.originalDomain.domain)}`,
    ],
  };
}
