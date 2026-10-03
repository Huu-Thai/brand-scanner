import { ThreatLevel } from '../../database/generated/prisma/enums.js';

/** Domain-scoring rule keys — must match `rule_configs.key` (seeded in migration 0004). */
export enum RuleKey {
  LEVENSHTEIN_DISTANCE = 'levenshtein_distance',
  SUSPICIOUS_TLD = 'suspicious_tld',
  SSL_ISSUES = 'ssl_issues',
  DMARC_MISSING = 'dmarc_missing',
  DOMAIN_AGE = 'domain_age',
  REPUTATION_CHECK = 'reputation_check',
  MX_RECORDS_FOUND = 'mx_records_found',
  DNS_RESOLVES = 'dns_resolves',
  LOW_TTL = 'low_ttl',
  SPAMHAUS_BLACKLIST = 'spamhaus_blacklist',
  VISUAL_SIMILARITY = 'visual_similarity',
  PHISHING_CONTENT = 'phishing_content',
}

export interface RulePointTier {
  condition: string;
  points: number;
}

export interface RuleConfigRecord {
  key: string;
  name: string;
  enabled: boolean;
  points: RulePointTier[];
  params: Record<string, unknown>;
}

export interface ScoringThresholds {
  thresholdMediumRisk: number;
  thresholdLowRisk: number;
}

export interface RuleScoringContext {
  configs: RuleConfigRecord[];
  thresholds: ScoringThresholds;
}

/** Signals for one look-alike. `undefined` = unknown → the owning rule cannot fire. */
export interface RuleEvaluationInput {
  originalDomain: string;
  fuzzerDomain: string;
  dns?: {
    a: string[];
    aaaa: string[];
    mx: string[];
    ns: string[];
    ttl: number | null;
  };
  whois?: { createdDate?: Date | null };
  /** Latest successful capture of the look-alike (absent until one exists). */
  page?: {
    perceptualHash: string | null;
    faviconHash: string | null;
    title: string | null;
    hasPasswordField: boolean;
    formActionHosts: string[];
    text: string;
  };
  /** The brand's own page (absent until captured). */
  reference?: { perceptualHash: string | null; faviconHash: string | null };
}

export type RuleSignalValue = string | number | boolean | null;

export interface RuleEvaluationResult {
  key: string;
  matched: boolean;
  condition: string | null;
  value: RuleSignalValue;
  points: number;
}

export interface RuleConditionResolution {
  condition: string;
  value: RuleSignalValue;
}

export interface DomainScoreResult {
  totalScore: number;
  threatLevel: ThreatLevel;
  thresholds: ScoringThresholds;
  ruleResults: RuleEvaluationResult[];
}

/** Same bands as Reporting: < low → LOW, < medium → MEDIUM, else HIGH. */
export function classify(
  totalScore: number,
  t: ScoringThresholds,
): ThreatLevel {
  if (totalScore < t.thresholdLowRisk) return ThreatLevel.LOW_RISK;
  if (totalScore < t.thresholdMediumRisk) return ThreatLevel.MEDIUM_RISK;
  return ThreatLevel.HIGH_RISK;
}
