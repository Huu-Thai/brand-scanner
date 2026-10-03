/**
 * Every named FK / unique constraint in the schema (PLAN.md §3.3), mapped to a
 * client-safe message. The migration e2e test asserts this list matches the
 * database exactly, so a new constraint can't ship without a message.
 */
export const FOREIGN_KEYS: Record<string, string> = {
  fk_scans_original_domain_id: 'Original domain does not exist',
  fk_scanned_domains_original_domain_id: 'Original domain does not exist',
  fk_scanned_domains_last_scan_id: 'Scan does not exist',
  fk_whois_informations_scanned_domain_id: 'Scanned domain does not exist',
  fk_screenshots_scanned_domain_id: 'Scanned domain does not exist',
  fk_screenshots_scan_id: 'Scan does not exist',
  fk_reviews_scanned_domain_id: 'Scanned domain does not exist',
  fk_analytics_scanned_domain_id: 'Scanned domain does not exist',
  fk_analytics_scan_id: 'Scan does not exist',
  fk_alert_subscriptions_channel_id: 'Alert channel does not exist',
  fk_alert_subscriptions_original_domain_id: 'Original domain does not exist',
  fk_alert_deliveries_subscription_id: 'Alert subscription does not exist',
  fk_alert_deliveries_channel_id: 'Alert channel does not exist',
  fk_alert_deliveries_scanned_domain_id: 'Scanned domain does not exist',
  fk_brand_references_original_domain_id: 'Original domain does not exist',
};

export const UNIQUE_CONSTRAINTS: Record<string, string> = {
  uq_original_domains_domain: 'This original domain is already registered',
  uq_scans_idempotency_key: 'A scan with this idempotency key already exists',
  uq_scans_active_original_domain:
    'A scan is already in progress for this original domain',
  uq_scanned_domains_original_domain_id_domain:
    'This domain is already tracked for the original domain',
  uq_screenshots_storage_key: 'A screenshot already uses this storage key',
  uq_rule_configs_key: 'A rule with this key already exists',
  uq_scoring_thresholds_key: 'A threshold set with this key already exists',
  uq_alert_channels_name: 'An alert channel with this name already exists',
  uq_alert_deliveries_dedupe_key: 'This alert was already raised',
  uq_brand_references_original_domain_id:
    'This brand already has a reference capture',
};

/** Extracts the violated constraint name from a Prisma 7 known-request error's `meta`. */
export function constraintFromMeta(meta: unknown): string | undefined {
  const m = meta as
    | {
        constraint?: unknown;
        target?: unknown;
        driverAdapterError?: {
          cause?: { constraint?: { index?: string } | string };
        };
      }
    | undefined;
  const cause = m?.driverAdapterError?.cause?.constraint;
  if (typeof cause === 'string') return cause;
  if (cause?.index) return cause.index;
  if (typeof m?.constraint === 'string') return m.constraint;
  return undefined;
}
