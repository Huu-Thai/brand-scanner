import type { ConfigService } from '@nestjs/config';
import type {
  HealthCheckService,
  HealthIndicatorFunction,
} from '@nestjs/terminus';
import type { AppConfig } from '../config/configuration.js';
import { HealthController } from './health.controller.js';
import type { HealthIndicators } from './health.indicators.js';

function setup(seleniumCheck: boolean) {
  const indicators = {
    database: vi.fn(async () => ({ database: { status: 'up' } })),
    redisPing: vi.fn(async () => ({ redis: { status: 'up' } })),
    objectStorage: vi.fn(async () => ({ storage: { status: 'up' } })),
    selenium: vi.fn(async () => ({ selenium: { status: 'up' } })),
  } as unknown as HealthIndicators;
  const health = {
    check: vi.fn(async (fns: HealthIndicatorFunction[]) =>
      Promise.all((fns as (() => Promise<unknown>)[]).map((f) => f())),
    ),
  } as unknown as HealthCheckService;
  const config = {
    get: () => ({ url: 'http://s:4444', healthCheck: seleniumCheck }),
  } as unknown as ConfigService<AppConfig, true>;
  return {
    controller: new HealthController(health, indicators, config),
    indicators,
  };
}

describe('HealthController', () => {
  it('checks database, redis, storage and selenium', async () => {
    const { controller, indicators } = setup(true);
    const results = (await controller.check()) as unknown as unknown[];
    expect(results).toHaveLength(4);
    expect(indicators.selenium).toHaveBeenCalled();
  });

  it('skips Selenium when HEALTH_CHECK_SELENIUM=false', async () => {
    const { controller, indicators } = setup(false);
    const results = (await controller.check()) as unknown as unknown[];
    expect(results).toHaveLength(3);
    expect(indicators.selenium).not.toHaveBeenCalled();
  });

  it('liveness does not touch dependencies', () => {
    const { controller, indicators } = setup(true);
    expect(controller.live()).toEqual({ status: 'ok' });
    expect(indicators.database).not.toHaveBeenCalled();
  });
});
