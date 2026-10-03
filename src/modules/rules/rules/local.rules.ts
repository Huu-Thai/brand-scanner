import { Injectable } from '@nestjs/common';
import { BaseRule } from '../base-rule.js';
import {
  type RuleConditionResolution,
  type RuleConfigRecord,
  type RuleEvaluationInput,
  RuleKey,
} from '../rule.types.js';

/** Rules that only read signals already collected (no network). Logic ported from Reporting. */

/** Plain Levenshtein distance, case-insensitive (Reporting's DP implementation). */
export function levenshtein(s1: string, s2: string): number {
  const a = s1.toLowerCase();
  const b = s2.toLowerCase();
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 0; i < a.length; i++) {
    const curr = [i + 1];
    for (let j = 0; j < b.length; j++) {
      curr.push(
        Math.min(
          prev[j + 1] + 1,
          curr[j] + 1,
          prev[j] + (a[i] !== b[j] ? 1 : 0),
        ),
      );
    }
    prev = curr;
  }
  return prev[b.length];
}

/** Close matches (distance 1–3) to the original domain → tier "4" (i.e. "< 4"). */
@Injectable()
export class LevenshteinDistanceRule extends BaseRule {
  readonly key = RuleKey.LEVENSHTEIN_DISTANCE;
  protected resolveCondition(
    input: RuleEvaluationInput,
  ): RuleConditionResolution {
    const distance = levenshtein(input.originalDomain, input.fuzzerDomain);
    return distance > 0 && distance < 4
      ? { condition: '4', value: distance }
      : { condition: 'default', value: distance };
  }
}

/** Last label in the configured high-abuse list (`params.tlds`, e.g. ".tk"). */
@Injectable()
export class SuspiciousTldRule extends BaseRule {
  readonly key = RuleKey.SUSPICIOUS_TLD;
  protected resolveCondition(
    input: RuleEvaluationInput,
    config: RuleConfigRecord,
  ): RuleConditionResolution {
    const tld = `.${input.fuzzerDomain.split('.').pop()}`;
    const configured = Array.isArray(config.params.tlds)
      ? (config.params.tlds as unknown[]).filter(
          (t): t is string => typeof t === 'string',
        )
      : [];
    return configured.some((c) => c.toLowerCase() === tld)
      ? { condition: 'matched', value: tld }
      : { condition: 'default', value: tld };
  }
}

/** Registered less than 30 days ago (WHOIS creation date). */
@Injectable()
export class DomainAgeRule extends BaseRule {
  readonly key = RuleKey.DOMAIN_AGE;
  protected resolveCondition(
    input: RuleEvaluationInput,
  ): RuleConditionResolution {
    const created = input.whois?.createdDate;
    if (!created) return { condition: 'default', value: 'not found' };
    const days = Math.floor((Date.now() - created.getTime()) / 86_400_000);
    return days < 30
      ? { condition: '30', value: days }
      : { condition: 'default', value: days };
  }
}

/** Has MX records — can send (phishing) email. */
@Injectable()
export class MxRecordsFoundRule extends BaseRule {
  readonly key = RuleKey.MX_RECORDS_FOUND;
  protected resolveCondition(
    input: RuleEvaluationInput,
  ): RuleConditionResolution {
    const mx = input.dns?.mx.filter((m) => m.trim()) ?? [];
    return mx.length
      ? { condition: 'exist', value: mx.join(',') }
      : { condition: 'default', value: 'does not exist' };
  }
}

/** Resolves to an IP address. */
@Injectable()
export class DnsResolvesRule extends BaseRule {
  readonly key = RuleKey.DNS_RESOLVES;
  protected resolveCondition(
    input: RuleEvaluationInput,
  ): RuleConditionResolution {
    const ip = input.dns?.a[0] ?? input.dns?.aaaa[0];
    return ip
      ? { condition: 'resolved_ip', value: ip }
      : { condition: 'default', value: 'no A/AAAA record' };
  }
}

/** Lowest A/AAAA TTL below 300 s — typical of fast-flux infrastructure. */
@Injectable()
export class LowTtlRule extends BaseRule {
  readonly key = RuleKey.LOW_TTL;
  protected resolveCondition(
    input: RuleEvaluationInput,
  ): RuleConditionResolution {
    const ttl = input.dns?.ttl;
    if (ttl === null || ttl === undefined)
      return { condition: 'default', value: 'not found' };
    return ttl < 300
      ? { condition: '300', value: ttl }
      : { condition: 'default', value: ttl };
  }
}
