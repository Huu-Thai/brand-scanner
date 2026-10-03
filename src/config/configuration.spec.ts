import configuration, { parseApiKeys } from './configuration.js';

describe('configuration', () => {
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
  });

  it('parses API key entries', () => {
    expect(
      parseApiKeys(`a:read:${'1'.repeat(64)}, b:admin:${'2'.repeat(64)}`),
    ).toEqual([
      { name: 'a', scope: 'read', hash: '1'.repeat(64) },
      { name: 'b', scope: 'admin', hash: '2'.repeat(64) },
    ]);
    expect(parseApiKeys(undefined)).toEqual([]);
  });

  it('defaults log format to json in production and pretty elsewhere', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.LOG_FORMAT;
    expect(configuration().log.format).toBe('json');
    process.env.NODE_ENV = 'development';
    expect(configuration().log.format).toBe('pretty');
    process.env.LOG_FORMAT = 'json';
    expect(configuration().log.format).toBe('json');
  });

  it('maps redis, s3, retention and worker settings', () => {
    Object.assign(process.env, {
      REDIS_HOST: 'r',
      REDIS_PORT: '6390',
      REDIS_PASSWORD: 'pw',
      REDIS_TLS: 'true',
      REDIS_USERNAME: '',
      S3_ENDPOINT: '',
      S3_FORCE_PATH_STYLE: 'true',
      RETENTION_DAYS: '31',
      RETENTION_KEEP_LATEST: 'false',
      WORKER_QUEUES: 'whois, screenshot ,',
    });
    const c = configuration();
    expect(c.redis).toMatchObject({
      host: 'r',
      port: 6390,
      password: 'pw',
      tls: true,
      username: undefined,
    });
    expect(c.s3).toMatchObject({ endpoint: undefined, forcePathStyle: true });
    expect(c.retention).toMatchObject({ days: 31, keepLatest: false });
    expect(c.worker.queues).toEqual(['whois', 'screenshot']);
  });
});
