import { validateEnv } from './validation.schema.js';

const HASH = 'a'.repeat(64);
const base = {
  DATABASE_URL: 'postgresql://u:p@localhost:5432/db',
  REDIS_HOST: 'localhost',
  REDIS_PASSWORD: 'dev-password',
  API_KEYS: `ci-reader:read:${HASH}`,
  S3_BUCKET: 'bucket',
  S3_ACCESS_KEY_ID: 'id',
  S3_SECRET_ACCESS_KEY: 'secret',
};

describe('validateEnv', () => {
  it('accepts a minimal valid environment and applies defaults', () => {
    const env = validateEnv(base);
    expect(env).toMatchObject({
      PORT: 3000,
      RETENTION_DAYS: 31,
      RETENTION_KEEP_LATEST: true,
      REDIS_QUEUE_DB: 0,
    });
  });

  it('refuses to start without REDIS_PASSWORD', () => {
    const { REDIS_PASSWORD: _omit, ...env } = base;
    expect(() => validateEnv(env)).toThrow(/REDIS_PASSWORD is required/);
  });

  it('rejects an empty REDIS_PASSWORD', () => {
    expect(() => validateEnv({ ...base, REDIS_PASSWORD: '' })).toThrow(
      /REDIS_PASSWORD/,
    );
  });

  it('requires at least 16 characters for REDIS_PASSWORD in production', () => {
    expect(() => validateEnv({ ...base, NODE_ENV: 'production' })).toThrow(
      /at least 16 characters/,
    );
    expect(() =>
      validateEnv({
        ...base,
        NODE_ENV: 'production',
        REDIS_PASSWORD: 'x'.repeat(16),
      }),
    ).not.toThrow();
  });

  it('rejects malformed API_KEYS entries', () => {
    expect(() => validateEnv({ ...base, API_KEYS: 'reader:root:abc' })).toThrow(
      /API_KEYS must be/,
    );
    expect(() =>
      validateEnv({
        ...base,
        API_KEYS: `a1:read:${HASH},b2:admin:${'b'.repeat(64)}`,
      }),
    ).not.toThrow();
  });

  it('reports every problem at once', () => {
    expect(() => validateEnv({})).toThrow(
      /DATABASE_URL[\s\S]*REDIS_HOST[\s\S]*REDIS_PASSWORD/,
    );
  });

  it('bounds RETENTION_DAYS to 1..365', () => {
    expect(() => validateEnv({ ...base, RETENTION_DAYS: '0' })).toThrow(
      /RETENTION_DAYS/,
    );
    expect(() => validateEnv({ ...base, RETENTION_DAYS: '400' })).toThrow(
      /RETENTION_DAYS/,
    );
  });

  it('allows an empty LOG_FORMAT (means: pick by environment)', () => {
    expect(() => validateEnv({ ...base, LOG_FORMAT: '' })).not.toThrow();
    expect(() => validateEnv({ ...base, LOG_FORMAT: 'xml' })).toThrow(
      /LOG_FORMAT/,
    );
  });
});
