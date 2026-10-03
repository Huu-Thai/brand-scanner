import type { ConfigService } from '@nestjs/config';
import { HealthIndicatorService } from '@nestjs/terminus';
import type { Redis } from 'ioredis';
import type { AppConfig } from '../config/configuration.js';
import type { PrismaService } from '../database/prisma.service.js';
import type { StorageService } from '../storage/storage.service.js';
import { HealthIndicators } from './health.indicators.js';

function setup(
  overrides: {
    db?: () => Promise<unknown>;
    ping?: () => Promise<string>;
    storage?: () => Promise<void>;
  } = {},
) {
  const prisma = {
    $queryRaw: vi.fn(overrides.db ?? (async () => [{ 1: 1 }])),
  } as unknown as PrismaService;
  const redis = {
    status: 'ready',
    connect: vi.fn(),
    ping: vi.fn(overrides.ping ?? (async () => 'PONG')),
  } as unknown as Redis;
  const storage = {
    bucket: 'b',
    ping: vi.fn(overrides.storage ?? (async () => undefined)),
  } as unknown as StorageService;
  const config = {
    get: () => ({ url: 'http://selenium:4444', healthCheck: true }),
  } as unknown as ConfigService<AppConfig, true>;
  return new HealthIndicators(
    new HealthIndicatorService(),
    prisma,
    redis,
    storage,
    config,
  );
}

describe('HealthIndicators', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('reports up when dependencies respond', async () => {
    const h = setup();
    expect((await h.database()).database.status).toBe('up');
    expect((await h.redisPing()).redis).toMatchObject({
      status: 'up',
      authenticated: true,
    });
    expect((await h.objectStorage()).storage).toMatchObject({
      status: 'up',
      bucket: 'b',
    });
  });

  it('reports down with the error message', async () => {
    const h = setup({
      db: async () => Promise.reject(new Error('db gone')),
      ping: async () =>
        Promise.reject(new Error('NOAUTH Authentication required.')),
      storage: async () => Promise.reject(new Error('NoSuchBucket')),
    });
    expect((await h.database()).database).toMatchObject({
      status: 'down',
      message: 'db gone',
    });
    expect((await h.redisPing()).redis).toMatchObject({
      status: 'down',
      message: 'NOAUTH Authentication required.',
    });
    expect((await h.objectStorage()).storage).toMatchObject({
      status: 'down',
      message: 'NoSuchBucket',
    });
  });

  it('checks Selenium Grid readiness via /status', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        status: 200,
        json: async () => ({ value: { ready: true, message: 'ok' } }),
      })),
    );
    expect((await setup().selenium()).selenium.status).toBe('up');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        status: 200,
        json: async () => ({ value: { ready: false, message: 'busy' } }),
      })),
    );
    expect((await setup().selenium()).selenium).toMatchObject({
      status: 'down',
      message: 'busy',
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Promise.reject(new Error('ECONNREFUSED'))),
    );
    expect((await setup().selenium()).selenium).toMatchObject({
      status: 'down',
      message: 'ECONNREFUSED',
    });
  });
});
