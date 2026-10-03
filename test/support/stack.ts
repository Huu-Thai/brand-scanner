import { createServer, type Server } from 'node:http';
import { CreateBucketCommand, S3Client } from '@aws-sdk/client-s3';
import {
  PostgreSqlContainer,
  type StartedPostgreSqlContainer,
} from '@testcontainers/postgresql';
import {
  RedisContainer,
  type StartedRedisContainer,
} from '@testcontainers/redis';
import {
  GenericContainer,
  type StartedTestContainer,
  Wait,
} from 'testcontainers';
import { hashApiKey } from '../../src/common/guards/api-key.guard.js';
import { prisma } from './migrate.js';

export const KEYS = {
  admin: 'fsk_e2e_admin_key_0123456789',
  reader: 'fsk_e2e_reader_key_0123456789',
};
export const REDIS_PASSWORD = 'e2e-redis-password-0123456789';
const MINIO = {
  user: 'e2e-access',
  password: 'e2e-secret-0123456789',
  bucket: 'fuzzer-screenshots-e2e',
};

export interface TestStack {
  redis: StartedRedisContainer;
  stop(): Promise<void>;
}

/** Starts Postgres (migrated), password-protected Redis, MinIO (+bucket) and a Selenium /status stub, then sets process.env. */
export async function startStack(): Promise<TestStack> {
  const [postgres, redis, minio] = await Promise.all([
    new PostgreSqlContainer('postgres:16-alpine').start(),
    new RedisContainer('redis:7-alpine').withPassword(REDIS_PASSWORD).start(),
    new GenericContainer('minio/minio:latest')
      .withCommand(['server', '/data'])
      .withEnvironment({
        MINIO_ROOT_USER: MINIO.user,
        MINIO_ROOT_PASSWORD: MINIO.password,
      })
      .withExposedPorts(9000)
      .withWaitStrategy(Wait.forHttp('/minio/health/ready', 9000))
      .start(),
  ]);

  const s3Endpoint = `http://${minio.getHost()}:${minio.getMappedPort(9000)}`;
  const s3 = new S3Client({
    endpoint: s3Endpoint,
    region: 'us-east-1',
    forcePathStyle: true,
    credentials: { accessKeyId: MINIO.user, secretAccessKey: MINIO.password },
  });
  await s3.send(new CreateBucketCommand({ Bucket: MINIO.bucket }));
  s3.destroy();

  const selenium = await seleniumStub();
  const databaseUrl = (
    postgres as StartedPostgreSqlContainer
  ).getConnectionUri();
  prisma(['migrate', 'deploy'], databaseUrl);

  Object.assign(process.env, {
    NODE_ENV: 'test',
    LOG_LEVEL: 'error',
    LOG_FORMAT: 'json',
    DATABASE_URL: databaseUrl,
    REDIS_HOST: redis.getHost(),
    REDIS_PORT: String(redis.getMappedPort(6379)),
    REDIS_PASSWORD,
    REDIS_USERNAME: '',
    API_KEYS: `e2e-admin:admin:${hashApiKey(KEYS.admin)},e2e-reader:read:${hashApiKey(KEYS.reader)}`,
    S3_ENDPOINT: s3Endpoint,
    S3_REGION: 'us-east-1',
    S3_BUCKET: MINIO.bucket,
    S3_ACCESS_KEY_ID: MINIO.user,
    S3_SECRET_ACCESS_KEY: MINIO.password,
    S3_FORCE_PATH_STYLE: 'true',
    SELENIUM_URL: selenium.url,
    HEALTH_CHECK_SELENIUM: 'true',
    THROTTLE_LIMIT: '1000',
    THROTTLE_EXPENSIVE_LIMIT: '1000',
  });

  return {
    redis,
    async stop() {
      await new Promise((resolve) => selenium.server.close(resolve));
      await Promise.all([
        postgres.stop(),
        redis.stop(),
        minio.stop(),
      ] as Promise<unknown>[]);
    },
  };
}

/** Minimal stand-in for Selenium Grid's GET /status (the real Grid is ~1 GB; not needed to test readiness wiring). */
function seleniumStub(): Promise<{ server: Server; url: string }> {
  const server = createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify({
        value: {
          ready: req.url === '/status',
          message: 'Selenium Grid ready.',
        },
      }),
    );
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as { port: number };
      resolve({ server, url: `http://127.0.0.1:${port}` });
    }),
  );
}

export type { StartedTestContainer };
