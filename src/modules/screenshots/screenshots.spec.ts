import { createServer } from 'node:http';
import type { ConfigService } from '@nestjs/config';
import type { Job } from 'bullmq';
import { error as seleniumError, type WebDriver } from 'selenium-webdriver';
import sharp from 'sharp';
import type { AppConfig } from '../../config/configuration.js';
import type { StorageService } from '../../storage/storage.service.js';
import { fakeBus } from '../../testing/fake-bus.js';
import type { ScannedDomainsQuery } from '../scanned-domains/scanned-domains.query.js';
import {
  ScannedDomainDiscoveredEvent,
  ScannedDomainUpdatedEvent,
} from '../scanned-domains/events/scanned-domain.events.js';
import { probeStatus } from './capture/http-probe.js';
import { analyzeImage, hashDistance } from './capture/image.js';
import {
  SeleniumCaptureService,
  SiteUnreachableError,
} from './capture/selenium-capture.service.js';
import { SCREENSHOT_EVENTS } from './events/screenshot.events.js';
import { ScreenshotTriggerListener } from './listeners/screenshot-trigger.listener.js';
import { ScreenshotProcessor } from './processors/screenshot.processor.js';
import type { ScreenshotEnqueuer } from './screenshot.enqueuer.js';
import { screenshotKey, ScreenshotsService } from './screenshots.service.js';
import { toScreenshotDto } from './screenshots.controller.js';

const png = (r: number, g: number, b: number, split = false) =>
  sharp({
    create: { width: 64, height: 32, channels: 3, background: { r, g, b } },
  })
    .composite(
      split
        ? [
            {
              input: {
                create: {
                  width: 32,
                  height: 32,
                  channels: 3,
                  background: { r: 255, g: 255, b: 255 },
                },
              },
              left: 32,
              top: 0,
            },
          ]
        : [],
    )
    .png()
    .toBuffer();

describe('image analysis', () => {
  it('reports size and a stable 64-bit dHash; similar images are close, different ones far', async () => {
    const a = await analyzeImage(await png(10, 10, 10, true));
    const b = await analyzeImage(await png(12, 12, 12, true));
    const c = await analyzeImage(await png(10, 10, 10));
    expect(a).toMatchObject({ width: 64, height: 32 });
    expect(a.perceptualHash).toMatch(/^[0-9a-f]{16}$/);
    expect(hashDistance(a.perceptualHash, b.perceptualHash)).toBe(0);
    expect(hashDistance(a.perceptualHash, c.perceptualHash)).toBeGreaterThan(0);
  });
});

describe('probeStatus', () => {
  it('returns the first status without following redirects, and null when unreachable', async () => {
    const server = createServer((_q, res) => {
      res.writeHead(302, { location: '/elsewhere' });
      res.end();
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const { port } = server.address() as { port: number };
    expect(await probeStatus(`http://127.0.0.1:${port}/`)).toBe(302);
    server.close();
    expect(await probeStatus('http://127.0.0.1:1/', 500)).toBeNull();
  });
});

class FakeCapture extends SeleniumCaptureService {
  constructor(private readonly driver: unknown) {
    super({ get: () => ({}) } as unknown as ConfigService<AppConfig, true>);
  }
  protected override async newSession(): Promise<WebDriver> {
    return this.driver as WebDriver;
  }
}

function driver(get: (url: string) => Promise<void>) {
  return {
    get: vi.fn(get),
    getCurrentUrl: vi.fn(async () => 'http://ww1.apypal.com/?tkn=1'),
    getTitle: vi.fn(async () => ' paypal '),
    takeScreenshot: vi.fn(async () => Buffer.from('png').toString('base64')),
    executeScript: vi.fn(async () => undefined),
    quit: vi.fn(async () => undefined),
  };
}

describe('SeleniumCaptureService', () => {
  it('captures https first and always quits the session', async () => {
    const d = driver(async () => undefined);
    const r = await new FakeCapture(d).capture('127.0.0.1');
    expect(r).toMatchObject({
      requestedUrl: 'https://127.0.0.1/',
      finalUrl: 'http://ww1.apypal.com/?tkn=1',
      pageTitle: 'paypal',
    });
    expect(r.png.toString()).toBe('png');
    expect(d.quit).toHaveBeenCalledOnce();
  });

  it('keeps a partial render on page-load timeout instead of failing', async () => {
    const d = driver(async () => {
      throw new seleniumError.TimeoutError(
        'timeout: Timed out receiving message from renderer: 18.5',
      );
    });
    const r = await new FakeCapture(d).capture('127.0.0.1');
    expect(d.executeScript).toHaveBeenCalledWith('window.stop();');
    expect(r.requestedUrl).toBe('https://127.0.0.1/');
  });

  it('falls back to http, then reports the site unreachable', async () => {
    const d = driver(async (url) => {
      if (url.startsWith('https'))
        throw new Error('unknown error: net::ERR_CONNECTION_REFUSED');
    });
    expect((await new FakeCapture(d).capture('127.0.0.1')).requestedUrl).toBe(
      'http://127.0.0.1/',
    );

    const dead = driver(async () => {
      throw new Error('unknown error: net::ERR_NAME_NOT_RESOLVED');
    });
    await expect(
      new FakeCapture(dead).capture('nope.invalid'),
    ).rejects.toBeInstanceOf(SiteUnreachableError);
    expect(dead.quit).toHaveBeenCalled();
  });

  it('rethrows Grid/session errors so the job retries', async () => {
    const d = driver(async () => {
      throw new Error('session not created: Could not start a new session');
    });
    await expect(new FakeCapture(d).capture('x.com')).rejects.toThrow(
      /session not created/,
    );
  });
});

describe('ScreenshotsService', () => {
  const capture = {
    png: Buffer.from('png'),
    requestedUrl: 'https://x.com/',
    finalUrl: 'https://x.com/',
    pageTitle: 't',
    httpStatus: 200,
  };
  const image = {
    width: 1366,
    height: 768,
    sizeBytes: 3,
    perceptualHash: 'ff00ff00ff00ff00',
  };

  function setup(failTx = false) {
    const storage = {
      bucket: 'b',
      putObject: vi.fn(
        async (_key: string, _body: Buffer, _type: string) => undefined,
      ),
      deleteObjects: vi.fn(async () => ({ deleted: [], failed: [] })),
    };
    const tx = {
      screenshot: {
        create: vi.fn(async ({ data }) => {
          if (failTx) throw new Error('db down');
          return { ...data };
        }),
      },
    };
    const bus = fakeBus(tx);
    return {
      service: new ScreenshotsService(
        bus.bus,
        storage as unknown as StorageService,
      ),
      storage,
      tx,
      ...bus,
    };
  }

  it('uploads first, then commits the row under a deterministic key', async () => {
    const t = setup();
    const row = await t.service.saveCaptured({
      scannedDomainId: 'sd',
      originalDomainId: 'od',
      scanId: 's',
      capture,
      image,
    });
    expect(t.storage.putObject).toHaveBeenCalledWith(
      screenshotKey('od', 'sd', row.id),
      capture.png,
      'image/png',
    );
    expect(row).toMatchObject({
      status: 'CAPTURED',
      storageKey: `screenshots/od/sd/${row.id}.png`,
      perceptualHash: image.perceptualHash,
    });
    expect(t.afterNames()).toEqual([SCREENSHOT_EVENTS.CAPTURED]);
  });

  it('deletes the uploaded object when the transaction fails (no orphans)', async () => {
    const t = setup(true);
    await expect(
      t.service.saveCaptured({
        scannedDomainId: 'sd',
        originalDomainId: 'od',
        capture,
        image,
      }),
    ).rejects.toThrow('db down');
    expect(t.storage.deleteObjects).toHaveBeenCalledWith([
      t.storage.putObject.mock.calls[0][0],
    ]);
  });

  it('records failures without an object', async () => {
    const t = setup();
    const row = await t.service.saveFailed('sd', 'x.com', 'x'.repeat(2000));
    expect(row).toMatchObject({
      status: 'FAILED',
      requestedUrl: 'https://x.com/',
    });
    expect(row.errorMessage).toHaveLength(1000);
    expect(t.afterNames()).toEqual([SCREENSHOT_EVENTS.FAILED]);
  });
});

describe('ScreenshotProcessor', () => {
  const sd = { id: 'sd', domain: 'x.com', originalDomainId: 'od' };
  function setup(captureImpl: () => Promise<unknown>) {
    const capture = {
      capture: vi.fn(captureImpl),
    } as unknown as SeleniumCaptureService;
    const screenshots = {
      saveCaptured: vi.fn(async (_input: unknown) => ({ id: 'shot' })),
      saveFailed: vi.fn(async () => ({ id: 'failed' })),
    };
    const scanned = {
      getForEnrichment: vi.fn(async () => sd),
    } as unknown as ScannedDomainsQuery;
    const config = {
      get: () => ({ screenshotConcurrency: 6 }),
    } as unknown as ConfigService<AppConfig, true>;
    const references = {
      captureNow: vi.fn(async () => ({ status: 'CAPTURED' })),
      refreshAll: vi.fn(async () => 3),
    };
    const p = new ScreenshotProcessor(
      capture,
      screenshots as unknown as ScreenshotsService,
      scanned,
      config,
      references as never,
    );
    return { p, screenshots, references };
  }
  const job = (attemptsMade = 1) =>
    ({
      id: 'j',
      queueName: 'screenshot',
      data: { scannedDomainId: 'sd', domain: 'x.com', scanId: 's' },
      attemptsMade,
      opts: { attempts: 2 },
    }) as unknown as Job;

  it('captures, analyses and saves', async () => {
    const real = await png(1, 2, 3);
    const { p, screenshots } = setup(async () => ({
      png: real,
      requestedUrl: 'u',
      finalUrl: 'f',
      pageTitle: null,
      httpStatus: 200,
    }));
    expect(await p.process(job())).toMatchObject({
      screenshotId: 'shot',
      finalUrl: 'f',
    });
    expect(screenshots.saveCaptured.mock.calls[0][0]).toMatchObject({
      image: { width: 64, height: 32 },
    });
  });

  it('records unreachable sites immediately; retries other errors and records FAILED after the last attempt', async () => {
    const dead = setup(async () => {
      throw new SiteUnreachableError('down');
    });
    expect(await dead.p.process(job())).toEqual({
      screenshotId: 'failed',
      failed: 'down',
    });

    const grid = setup(async () => {
      throw new Error('grid busy');
    });
    await expect(grid.p.process(job())).rejects.toThrow('grid busy');
    await grid.p.onFailed(job(1), new Error('grid busy'));
    expect(grid.screenshots.saveFailed).not.toHaveBeenCalled();
    await grid.p.onFailed(job(2), new Error('grid busy'));
    expect(grid.screenshots.saveFailed).toHaveBeenCalledWith(
      'sd',
      'x.com',
      'capture failed: grid busy',
      's',
    );
  });
});

describe('ScreenshotTriggerListener', () => {
  const flags = { whois: true, screenshots: true };
  it('captures new resolving look-alikes, first enrichments, and web-facing DNS changes only', async () => {
    const enqueuer = {
      enqueue: vi.fn(async (_data: { scannedDomainId: string }) => 'j'),
    } as unknown as ScreenshotEnqueuer & { enqueue: ReturnType<typeof vi.fn> };
    const l = new ScreenshotTriggerListener(enqueuer);
    await l.onDiscovered(
      new ScannedDomainDiscoveredEvent('a', 'od', 's', 'a.com', true, flags),
    );
    await l.onDiscovered(
      new ScannedDomainDiscoveredEvent('b', 'od', 's', 'b.com', false, flags),
    ); // no IP
    await l.onDiscovered(
      new ScannedDomainDiscoveredEvent('c', 'od', 's', 'c.com', true, {
        ...flags,
        screenshots: false,
      }),
    );
    await l.onUpdated(
      new ScannedDomainUpdatedEvent(
        'd',
        'od',
        's',
        'd.com',
        ['dnsMx'],
        true,
        flags,
      ),
    ); // mail only
    await l.onUpdated(
      new ScannedDomainUpdatedEvent(
        'e',
        'od',
        's',
        'e.com',
        ['dnsA'],
        true,
        flags,
      ),
    );
    await l.onUpdated(
      new ScannedDomainUpdatedEvent(
        'f',
        'od',
        's',
        'f.com',
        [],
        true,
        flags,
        true,
      ),
    ); // first enrichment
    expect(
      enqueuer.enqueue.mock.calls.map((c) => c[0].scannedDomainId),
    ).toEqual(['a', 'e', 'f']);
  });
});

describe('toScreenshotDto', () => {
  it('exposes an image URL only when an object exists', () => {
    expect(
      toScreenshotDto({ id: 'i', storageKey: 'k' } as never).imageUrl,
    ).toBe('/api/v1/screenshots/i/image');
    expect(
      toScreenshotDto({ id: 'i', storageKey: null } as never).imageUrl,
    ).toBeNull();
  });
});
