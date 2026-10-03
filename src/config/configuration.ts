export type ApiKeyScope = 'read' | 'write' | 'admin';

export interface ApiKeyEntry {
  name: string;
  scope: ApiKeyScope;
  /** SHA-256 hex digest of the raw key — raw keys are never stored. */
  hash: string;
}

export interface AppConfig {
  env: 'development' | 'production' | 'test';
  port: number;
  log: {
    level: string;
    format: 'json' | 'pretty';
    toFile: boolean;
    dir: string;
  };
  database: { url: string };
  redis: {
    host: string;
    port: number;
    username?: string;
    password: string;
    tls: boolean;
    queueDb: number;
    cacheDb: number;
  };
  apiKeys: ApiKeyEntry[];
  /** Key names that may set `x-acting-user`. */
  trustedProxyKeys: string[];
  export: { maxRows: number };
  s3: {
    endpoint?: string;
    region: string;
    bucket: string;
    accessKeyId: string;
    secretAccessKey: string;
    forcePathStyle: boolean;
    signedUrlTtl: number;
    serverSideEncryption?: 'AES256' | 'aws:kms';
  };
  selenium: { url: string; healthCheck: boolean };
  dns: {
    nameservers: string[];
    timeoutMs: number;
    retries: number;
    concurrency: number;
  };
  scan: { batchSize: number; maxPermutations: number };
  enrichment: {
    /** IANA RDAP bootstrap (override for an internal mirror or the load-test stub). */
    rdapBootstrapUrl: string;
    whoisRefreshDays: number;
    whoisTimeoutMs: number;
    screenshotPageTimeoutMs: number;
    screenshotConcurrency: number;
    ruleNetworkTimeoutMs: number;
    rulesCacheTtlMs: number;
  };
  threatFeed: {
    enabled: boolean;
    pushEnabled: boolean;
    sourceName: string;
    /** Skips the source lookup (and the need for sources:read on the service account). */
    sourceId?: string;
    url?: string;
    email?: string;
    password?: string;
    timeoutMs: number;
    cacheTtlSeconds: number;
    missTtlSeconds: number;
  };
  processRole: 'api' | 'worker';
  auth: { jwtSecret?: string; identityCacheMs: number };
  ct: {
    enabled: boolean;
    streamUrl: string;
    minKeywordLength: number;
    maxEditDistance: number;
    stallTimeoutMs: number;
  };
  alerts: {
    encryptionKey?: string;
    digestCron: string;
    consoleUrl?: string;
    allowPrivateTargets: boolean;
    allowInsecureTargets: boolean;
    timeoutMs: number;
    smtpUrl?: string;
    emailFrom: string;
  };
  metrics: { token?: string; port: number };
  outbox: {
    relayEnabled: boolean;
    relayIntervalMs: number;
    graceMs: number;
    maxAttempts: number;
  };
  retention: {
    days: number;
    keepLatest: boolean;
    cron: string;
    sweepCron: string;
    batchSize: number;
    orphanMinAgeMs: number;
  };
  throttle: { ttlMs: number; limit: number };
  swagger: { enabled: boolean };
  worker: { queues: string[] };
}

/** Same pool as Reporting's DNS_NAMESERVERS (Cloudflare, Google, Quad9, OpenDNS, …). */
export const DEFAULT_NAMESERVERS = [
  '1.1.1.1',
  '1.0.0.1',
  '8.8.8.8',
  '8.8.4.4',
  '9.9.9.9',
  '149.112.112.112',
  '208.67.222.222',
  '208.67.220.220',
  '76.76.19.19',
  '76.223.100.101',
  '94.140.14.14',
  '94.140.15.15',
  '8.26.56.26',
  '8.20.247.20',
  '185.228.168.9',
  '185.228.169.9',
];

const list = (value: string | undefined) =>
  (value ?? '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);

const int = (value: string | undefined, fallback: number) =>
  value === undefined || value === '' ? fallback : parseInt(value, 10);

const flag = (value: string | undefined, fallback: boolean) =>
  value === undefined || value === '' ? fallback : value === 'true';

export function parseApiKeys(raw: string | undefined): ApiKeyEntry[] {
  if (!raw) return [];
  return raw.split(',').map((entry) => {
    const [name, scope, hash] = entry.trim().split(':');
    return { name, scope: scope as ApiKeyScope, hash };
  });
}

/** Typed view over the (already Joi-validated) environment. */
export default (): AppConfig => {
  const env = (process.env.NODE_ENV ?? 'development') as AppConfig['env'];
  return {
    env,
    port: parseInt(process.env.PORT ?? '3000', 10),
    log: {
      level: process.env.LOG_LEVEL ?? 'info',
      format:
        (process.env.LOG_FORMAT as 'json' | 'pretty' | undefined) ??
        (env === 'production' ? 'json' : 'pretty'),
      toFile: flag(process.env.LOG_TO_FILE, false),
      dir: process.env.LOG_DIR ?? 'logs',
    },
    database: { url: process.env.DATABASE_URL as string },
    redis: {
      host: process.env.REDIS_HOST as string,
      port: parseInt(process.env.REDIS_PORT ?? '6379', 10),
      username: process.env.REDIS_USERNAME || undefined,
      password: process.env.REDIS_PASSWORD as string,
      tls: flag(process.env.REDIS_TLS, false),
      queueDb: parseInt(process.env.REDIS_QUEUE_DB ?? '0', 10),
      cacheDb: parseInt(process.env.REDIS_CACHE_DB ?? '1', 10),
    },
    apiKeys: parseApiKeys(process.env.API_KEYS),
    trustedProxyKeys: list(process.env.TRUSTED_PROXY_KEYS),
    export: { maxRows: int(process.env.EXPORT_MAX_ROWS, 100_000) },
    s3: {
      endpoint: process.env.S3_ENDPOINT || undefined,
      region: process.env.S3_REGION ?? 'us-east-1',
      bucket: process.env.S3_BUCKET as string,
      accessKeyId: process.env.S3_ACCESS_KEY_ID as string,
      secretAccessKey: process.env.S3_SECRET_ACCESS_KEY as string,
      forcePathStyle: flag(process.env.S3_FORCE_PATH_STYLE, false),
      signedUrlTtl: parseInt(process.env.S3_SIGNED_URL_TTL ?? '300', 10),
      serverSideEncryption: (process.env.S3_SSE ||
        undefined) as AppConfig['s3']['serverSideEncryption'],
    },
    selenium: {
      url: process.env.SELENIUM_URL ?? 'http://localhost:4444',
      healthCheck: flag(process.env.HEALTH_CHECK_SELENIUM, true),
    },
    dns: {
      nameservers: list(process.env.DNS_NAMESERVERS).length
        ? list(process.env.DNS_NAMESERVERS)
        : DEFAULT_NAMESERVERS,
      timeoutMs: parseInt(process.env.DNS_TIMEOUT_MS ?? '3000', 10),
      retries: parseInt(process.env.DNS_RETRIES ?? '2', 10),
      concurrency: parseInt(process.env.DNS_CONCURRENCY ?? '100', 10),
    },
    scan: {
      batchSize: parseInt(process.env.SCAN_BATCH_SIZE ?? '500', 10),
      maxPermutations: parseInt(
        process.env.SCAN_MAX_PERMUTATIONS ?? '150000',
        10,
      ),
    },
    enrichment: {
      rdapBootstrapUrl:
        process.env.RDAP_BOOTSTRAP_URL || 'https://data.iana.org/rdap/dns.json',
      whoisRefreshDays: int(process.env.WHOIS_REFRESH_DAYS, 7),
      whoisTimeoutMs: int(process.env.WHOIS_TIMEOUT_MS, 10_000),
      screenshotPageTimeoutMs: int(
        process.env.SCREENSHOT_PAGE_TIMEOUT_MS,
        20_000,
      ),
      screenshotConcurrency: int(process.env.SCREENSHOT_CONCURRENCY, 4),
      ruleNetworkTimeoutMs: int(process.env.RULE_NETWORK_TIMEOUT_MS, 5_000),
      rulesCacheTtlMs: int(process.env.RULES_CACHE_TTL_MS, 60_000),
    },
    threatFeed: {
      enabled: flag(process.env.THREAT_FEED_ENABLED, false),
      pushEnabled: flag(process.env.THREAT_FEED_PUSH_ENABLED, false),
      sourceName: process.env.THREAT_FEED_SOURCE_NAME || 'Fuzzer Scanner',
      sourceId: process.env.THREAT_FEED_SOURCE_ID || undefined,
      url: process.env.THREAT_FEED_URL?.replace(/\/+$/, '') || undefined,
      email: process.env.THREAT_FEED_EMAIL || undefined,
      password: process.env.THREAT_FEED_PASSWORD || undefined,
      timeoutMs: int(process.env.THREAT_FEED_TIMEOUT_MS, 5_000),
      cacheTtlSeconds: int(process.env.REPUTATION_CACHE_TTL_S, 3_600),
      missTtlSeconds: int(process.env.REPUTATION_MISS_TTL_S, 600),
    },
    auth: {
      jwtSecret: process.env.AUTH_JWT_SECRET || undefined,
      identityCacheMs: int(process.env.AUTH_IDENTITY_CACHE_MS, 60_000),
    },
    ct: {
      enabled: flag(process.env.CT_MONITOR_ENABLED, false),
      streamUrl: process.env.CT_STREAM_URL || 'wss://certstream.calidog.io/',
      minKeywordLength: int(process.env.CT_MIN_KEYWORD_LENGTH, 5),
      maxEditDistance: int(process.env.CT_MAX_EDIT_DISTANCE, 2),
      stallTimeoutMs: int(process.env.CT_STALL_TIMEOUT_MS, 120_000),
    },
    alerts: {
      encryptionKey: process.env.ALERT_ENCRYPTION_KEY || undefined,
      digestCron: process.env.ALERT_DIGEST_CRON || '0 8 * * *',
      consoleUrl:
        process.env.ALERT_CONSOLE_URL?.replace(/\/+$/, '') || undefined,
      allowPrivateTargets: flag(process.env.ALERT_ALLOW_PRIVATE_TARGETS, false),
      allowInsecureTargets: flag(
        process.env.ALERT_ALLOW_INSECURE_TARGETS,
        false,
      ),
      timeoutMs: int(process.env.ALERT_TIMEOUT_MS, 10_000),
      smtpUrl: process.env.SMTP_URL || undefined,
      emailFrom:
        process.env.ALERT_EMAIL_FROM ||
        'Fuzzer Scanner <alerts@fuzzer-scanner.local>',
    },
    metrics: {
      token: process.env.METRICS_TOKEN || undefined,
      port: int(process.env.METRICS_PORT, 9464),
    },
    processRole: process.env.PROCESS_ROLE === 'worker' ? 'worker' : 'api',
    outbox: {
      relayEnabled: flag(process.env.OUTBOX_RELAY_ENABLED, true),
      relayIntervalMs: int(process.env.OUTBOX_RELAY_INTERVAL_MS, 5_000),
      graceMs: int(process.env.OUTBOX_GRACE_MS, 30_000),
      maxAttempts: int(process.env.OUTBOX_MAX_ATTEMPTS, 10),
    },
    retention: {
      days: parseInt(process.env.RETENTION_DAYS ?? '31', 10),
      keepLatest: flag(process.env.RETENTION_KEEP_LATEST, true),
      cron: process.env.RETENTION_CRON || '30 3 * * *',
      sweepCron: process.env.RETENTION_SWEEP_CRON || '0 4 * * 0',
      batchSize: int(process.env.RETENTION_BATCH_SIZE, 5_000),
      orphanMinAgeMs: int(process.env.RETENTION_ORPHAN_MIN_AGE_MS, 3_600_000),
    },
    throttle: {
      ttlMs: parseInt(process.env.THROTTLE_TTL_MS ?? '60000', 10),
      limit: parseInt(process.env.THROTTLE_LIMIT ?? '120', 10),
    },
    swagger: { enabled: flag(process.env.SWAGGER_ENABLED, true) },
    worker: { queues: list(process.env.WORKER_QUEUES) },
  };
};
