import { isValidCron } from '../common/validators/is-cron.validator.js';
import Joi from 'joi';

/**
 * `name:scope:sha256hex` entries, comma separated. Scope is read | write | admin.
 * Generate with `npm run apikey:generate -- <name> <scope>`.
 */
export const API_KEYS_PATTERN =
  /^[a-z0-9][a-z0-9._-]{1,63}:(read|write|admin):[a-f0-9]{64}(,[a-z0-9][a-z0-9._-]{1,63}:(read|write|admin):[a-f0-9]{64})*$/;

const bool = () => Joi.boolean().truthy('true').falsy('false');

const cron = () =>
  Joi.string().custom((value: string, helpers) =>
    isValidCron(value)
      ? value
      : helpers.message({
          custom: `"${value}" is not a valid cron expression`,
        }),
  );

export const validationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  PORT: Joi.number().port().default(3000),

  LOG_LEVEL: Joi.string()
    .valid('error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly')
    .default('info'),
  LOG_FORMAT: Joi.string().valid('json', 'pretty').allow('').optional(),
  LOG_TO_FILE: bool().default(false),
  LOG_DIR: Joi.string().default('logs'),

  DATABASE_URL: Joi.string()
    .uri({ scheme: ['postgres', 'postgresql'] })
    .required(),

  REDIS_HOST: Joi.string().required(),
  REDIS_PORT: Joi.number().port().default(6379),
  REDIS_USERNAME: Joi.string().allow('').optional(),
  // Password is mandatory in every environment; production also enforces a minimum length.
  REDIS_PASSWORD: Joi.string()
    .required()
    .when('NODE_ENV', {
      is: 'production',
      // oxlint-disable-next-line unicorn/no-thenable -- Joi's conditional API uses `then`
      then: Joi.string().min(16),
      otherwise: Joi.string().min(1),
    })
    .messages({
      'any.required':
        'REDIS_PASSWORD is required — the service never connects to Redis without authentication',
      'string.min':
        'REDIS_PASSWORD must be at least {#limit} characters in this environment',
    }),
  REDIS_TLS: bool().default(false),
  REDIS_QUEUE_DB: Joi.number().integer().min(0).max(15).default(0),
  REDIS_CACHE_DB: Joi.number().integer().min(0).max(15).default(1),

  API_KEYS: Joi.string().pattern(API_KEYS_PATTERN).required().messages({
    'string.pattern.base':
      'API_KEYS must be comma-separated "name:scope:sha256hex" entries (scope = read|write|admin)',
  }),

  // API-key names allowed to assert the acting end user via `x-acting-user` (e.g. manage-feed's gateway key).
  TRUSTED_PROXY_KEYS: Joi.string().allow('').default(''),

  S3_ENDPOINT: Joi.string().uri().allow('').optional(),
  S3_REGION: Joi.string().default('us-east-1'),
  S3_BUCKET: Joi.string().required(),
  S3_ACCESS_KEY_ID: Joi.string().required(),
  S3_SECRET_ACCESS_KEY: Joi.string().required(),
  S3_FORCE_PATH_STYLE: bool().default(false),
  // Explicit SSE header. Empty = rely on the bucket's default encryption (S3 encrypts all new
  // objects by default; MinIO rejects SSE headers unless a KMS is configured).
  S3_SSE: Joi.string().valid('', 'AES256', 'aws:kms').default(''),
  S3_SIGNED_URL_TTL: Joi.number().integer().min(30).max(3600).default(300),

  SELENIUM_URL: Joi.string().uri().default('http://localhost:4444'),
  HEALTH_CHECK_SELENIUM: bool().default(true),

  // Comma-separated resolver IPs. Default: the same 16 public resolvers Reporting uses.
  DNS_NAMESERVERS: Joi.string()
    .pattern(/^[0-9a-fA-F.:]+(,\s*[0-9a-fA-F.:]+)*$/)
    .allow('')
    .optional(),
  DNS_TIMEOUT_MS: Joi.number().integer().min(200).max(30_000).default(3_000),
  DNS_RETRIES: Joi.number().integer().min(0).max(5).default(2),
  DNS_CONCURRENCY: Joi.number().integer().min(1).max(1_000).default(100),
  SCAN_BATCH_SIZE: Joi.number().integer().min(10).max(5_000).default(500),
  SCAN_MAX_PERMUTATIONS: Joi.number().integer().min(100).default(150_000),

  // Enrichment
  WHOIS_REFRESH_DAYS: Joi.number().integer().min(0).max(365).default(7),
  RDAP_BOOTSTRAP_URL: Joi.string()
    .uri({ scheme: ['http', 'https'] })
    .optional(),
  WHOIS_TIMEOUT_MS: Joi.number()
    .integer()
    .min(1_000)
    .max(60_000)
    .default(10_000),
  SCREENSHOT_PAGE_TIMEOUT_MS: Joi.number()
    .integer()
    .min(5_000)
    .max(120_000)
    .default(20_000),
  SCREENSHOT_CONCURRENCY: Joi.number().integer().min(1).max(64).default(4),
  RULE_NETWORK_TIMEOUT_MS: Joi.number()
    .integer()
    .min(500)
    .max(30_000)
    .default(5_000),
  RULES_CACHE_TTL_MS: Joi.number()
    .integer()
    .min(0)
    .max(3_600_000)
    .default(60_000),

  // Reputation source: indicators curated in manage-feed, served by the threat-feed API.
  THREAT_FEED_ENABLED: bool().default(false),
  THREAT_FEED_URL: Joi.string()
    .uri({ scheme: ['http', 'https'] })
    // oxlint-disable-next-line unicorn/no-thenable -- Joi's conditional API uses `then`
    .when('THREAT_FEED_ENABLED', {
      is: true,
      // oxlint-disable-next-line unicorn/no-thenable -- Joi's conditional API uses `then`
      then: Joi.required(),
      otherwise: Joi.optional().allow(''),
    }),
  THREAT_FEED_EMAIL: Joi.string()
    .email({ tlds: false })
    // oxlint-disable-next-line unicorn/no-thenable -- Joi's conditional API uses `then`
    .when('THREAT_FEED_ENABLED', {
      is: true,
      // oxlint-disable-next-line unicorn/no-thenable -- Joi's conditional API uses `then`
      then: Joi.required(),
      otherwise: Joi.optional().allow(''),
    }),
  THREAT_FEED_PASSWORD: Joi.string().when('THREAT_FEED_ENABLED', {
    is: true,
    // oxlint-disable-next-line unicorn/no-thenable -- Joi's conditional API uses `then`
    then: Joi.required(),
    otherwise: Joi.optional().allow(''),
  }),
  // Push analyst-confirmed threats into threat-feed (needs POST/PATCH /feeds on the service role).
  // Publishing confirmed threats needs the threat-feed credentials above.
  THREAT_FEED_PUSH_ENABLED: bool()
    .default(false)
    .when('THREAT_FEED_ENABLED', {
      is: false,
      // oxlint-disable-next-line unicorn/no-thenable -- Joi's conditional API uses `then`
      then: Joi.valid(false).messages({
        'any.only':
          'THREAT_FEED_PUSH_ENABLED requires THREAT_FEED_ENABLED=true',
      }),
    }),
  THREAT_FEED_SOURCE_NAME: Joi.string()
    .min(2)
    .max(100)
    .default('Fuzzer Scanner'),
  THREAT_FEED_SOURCE_ID: Joi.string().guid().optional(),
  THREAT_FEED_TIMEOUT_MS: Joi.number()
    .integer()
    .min(500)
    .max(30_000)
    .default(5_000),
  REPUTATION_CACHE_TTL_S: Joi.number().integer().min(0).default(3_600),
  REPUTATION_MISS_TTL_S: Joi.number().integer().min(0).default(600),

  EXPORT_MAX_ROWS: Joi.number()
    .integer()
    .min(100)
    .max(1_000_000)
    .default(100_000),

  // Bearer token for /metrics (API) and the worker metrics port; empty = open (scrape on a private network).
  METRICS_TOKEN: Joi.string().min(16).allow('').optional(),
  METRICS_PORT: Joi.number().port().default(9464), // 0 = no worker metrics server

  // ─── Alerting (Phase 5) ───
  // 32-byte key (64 hex chars or base64) encrypting alert targets and signing secrets at rest.
  ALERT_ENCRYPTION_KEY: Joi.string()
    .pattern(/^([0-9a-fA-F]{64}|[A-Za-z0-9+/]{43}=?)$/)
    .optional()
    .messages({
      'string.pattern.base':
        'ALERT_ENCRYPTION_KEY must be 32 bytes (64 hex chars or base64)',
    }),
  ALERT_DIGEST_CRON: cron().default('0 8 * * *'),
  // Deep links in alerts, e.g. https://console.example.com (manage-feed) → /lookalikes/<id>.
  ALERT_CONSOLE_URL: Joi.string()
    .uri({ scheme: ['http', 'https'] })
    .optional(),
  // SSRF guard for webhook / Slack targets: https only, public addresses only — unless relaxed.
  ALERT_ALLOW_PRIVATE_TARGETS: bool().default(false),
  ALERT_ALLOW_INSECURE_TARGETS: bool().default(false),
  ALERT_TIMEOUT_MS: Joi.number().integer().min(500).max(60_000).default(10_000),
  // E-mail channel: smtp(s)://user:pass@host:port and the From address.
  SMTP_URL: Joi.string()
    .uri({ scheme: ['smtp', 'smtps'] })
    .optional(),
  ALERT_EMAIL_FROM: Joi.string().default(
    'Fuzzer Scanner <alerts@fuzzer-scanner.local>',
  ),

  // ─── Certificate Transparency monitoring (Phase 5) ───
  CT_MONITOR_ENABLED: bool().default(false),
  // certstream-compatible WebSocket (full or /domains-only). Self-host certstream-server-go in production.
  CT_STREAM_URL: Joi.string()
    .uri({ scheme: ['ws', 'wss'] })
    .default('wss://certstream.calidog.io/'),
  CT_MIN_KEYWORD_LENGTH: Joi.number().integer().min(3).max(20).default(5),
  CT_MAX_EDIT_DISTANCE: Joi.number().integer().min(1).max(3).default(2),
  // Reconnect when the stream is silent this long.
  CT_STALL_TIMEOUT_MS: Joi.number().integer().min(5_000).default(120_000),

  // ─── Shared auth with threat-feed (Phase 5) ───
  // threat-feed's JWT_SECRET: Bearer user tokens are then accepted alongside API keys.
  AUTH_JWT_SECRET: Joi.string().min(16).optional(),
  AUTH_IDENTITY_CACHE_MS: Joi.number()
    .integer()
    .min(0)
    .max(600_000)
    .default(60_000),

  // Set by the entry point (worker.main.ts → worker); not normally configured by hand.
  PROCESS_ROLE: Joi.string().valid('api', 'worker').default('api'),
  OUTBOX_RELAY_ENABLED: bool().default(true),
  OUTBOX_RELAY_INTERVAL_MS: Joi.number()
    .integer()
    .min(500)
    .max(300_000)
    .default(5_000),
  // How long the producing process has to dispatch before the relay may take over.
  OUTBOX_GRACE_MS: Joi.number()
    .integer()
    .min(1_000)
    .max(3_600_000)
    .default(30_000),
  OUTBOX_MAX_ATTEMPTS: Joi.number().integer().min(1).max(100).default(10),

  RETENTION_DAYS: Joi.number().integer().min(1).max(365).default(31),
  RETENTION_KEEP_LATEST: bool().default(true),
  RETENTION_CRON: cron().default('30 3 * * *'),
  RETENTION_SWEEP_CRON: cron().default('0 4 * * 0'),
  RETENTION_ORPHAN_MIN_AGE_MS: Joi.number().integer().min(0).default(3_600_000),
  RETENTION_BATCH_SIZE: Joi.number()
    .integer()
    .min(100)
    .max(50_000)
    .default(5_000),

  THROTTLE_TTL_MS: Joi.number().integer().min(1000).default(60_000),
  THROTTLE_EXPENSIVE_LIMIT: Joi.number().integer().min(1).default(10),
  THROTTLE_LIMIT: Joi.number().integer().min(1).default(120),

  SWAGGER_ENABLED: bool().default(true),
  WORKER_QUEUES: Joi.string().allow('').optional(),
})
  // User tokens are resolved through threat-feed's GET /auth/me.
  .with('AUTH_JWT_SECRET', 'THREAT_FEED_URL');

/**
 * Validates the raw environment, reporting every problem at once. Throwing here
 * aborts bootstrap, so a misconfigured process never starts.
 */
export function validateEnv(
  env: Record<string, unknown>,
): Record<string, unknown> {
  const { error, value } = validationSchema.validate(env, {
    abortEarly: false,
    allowUnknown: true,
    convert: true,
  });
  if (error) {
    const details = error.details.map((d) => `  - ${d.message}`).join('\n');
    throw new Error(`Invalid environment configuration:\n${details}`);
  }
  return value as Record<string, unknown>;
}
