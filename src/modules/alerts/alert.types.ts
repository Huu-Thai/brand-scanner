import type {
  AlertEventType,
  ThreatLevel,
  DomainStatus,
} from '../../database/generated/prisma/enums.js';

/** What one alert is about (stored on the delivery, rendered by every channel). */
export interface AlertPayload {
  eventType: AlertEventType;
  scannedDomainId: string;
  domain: string;
  unicodeDomain: string;
  brand: string;
  originalDomainId: string;
  fuzzer: string;
  riskScore: number;
  threatLevel: ThreatLevel;
  status: DomainStatus;
  /** Extra context, e.g. matched scoring rules for HIGH_RISK. */
  details: string[];
  consoleUrl: string | null;
  occurredAt: string;
}

export const EVENT_TITLES: Record<AlertEventType, string> = {
  HIGH_RISK: 'High-risk look-alike',
  NEW_LOOKALIKE: 'New look-alike registered',
  WENT_LIVE: 'Look-alike is live again',
  CONFIRMED_THREAT: 'Look-alike confirmed as a threat',
};

export function headline(p: AlertPayload): string {
  return `${EVENT_TITLES[p.eventType]}: ${p.domain} (imitates ${p.brand}, risk ${p.riskScore})`;
}

/** Masks a target for display: URLs keep scheme + host + last 4 chars, e-mails keep the domain. */
export function maskTarget(
  type: 'WEBHOOK' | 'SLACK' | 'EMAIL',
  target: string,
): string {
  if (type === 'EMAIL')
    return target
      .split(',')
      .map((e) => e.trim())
      .map((e) => `${e[0] ?? ''}***@${e.split('@')[1] ?? ''}`)
      .join(', ')
      .slice(0, 200);
  try {
    const u = new URL(target);
    const tail = (u.pathname + u.search).slice(-4);
    return `${u.protocol}//${u.host}/…${tail}`.slice(0, 200);
  } catch {
    return '…';
  }
}
