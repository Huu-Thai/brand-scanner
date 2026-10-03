import { HttpException, NotFoundException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { EventEmitter2 } from '@nestjs/event-emitter';
import type { FlowProducer, Job } from 'bullmq';
import type { AppConfig } from '../../../config/configuration.js';
import type { DnsResolverService } from '../../dns-resolver/dns-resolver.service.js';
import type { FuzzerService } from '../../fuzzer/fuzzer.service.js';
import type { OriginalDomainsQuery } from '../../original-domains/original-domains.query.js';
import type { ScannedDomainsQuery } from '../../scanned-domains/scanned-domains.query.js';
import { SCAN_EVENTS } from '../events/scan.events.js';
import type { ScansService } from '../scans.service.js';
import { DnsResolveProcessor } from './dns-resolve.processor.js';
import {
  batchSizeAt,
  ScanFinalizeProcessor,
} from './scan-finalize.processor.js';
import { ScanOrchestratorProcessor } from './scan-orchestrator.processor.js';
import { ScheduledScanProcessor } from './scheduled-scan.processor.js';

const job = <T>(data: T, over: Partial<Job> = {}) =>
  ({
    id: 'job-1',
    queueName: 'q',
    data,
    attemptsMade: 1,
    opts: { attempts: 3 },
    ...over,
  }) as unknown as Job<T>;

function scans(status = 'QUEUED', options: object = {}) {
  return {
    get: vi.fn(async () => ({
      id: 'scan-1',
      originalDomainId: 'od-1',
      status,
      options,
      startedAt: new Date(0),
    })),
    startFuzzing: vi.fn(async () => ({
      id: 'scan-1',
      originalDomainId: 'od-1',
      status: 'FUZZING',
      options,
    })),
    startResolving: vi.fn(async () => ({})),
    complete: vi.fn(async () => ({})),
    fail: vi.fn(async () => ({})),
    recordProgress: vi.fn(async () => undefined),
    create: vi.fn(),
  };
}

describe('ScanOrchestratorProcessor', () => {
  const config = {
    get: () => ({ batchSize: 2, maxPermutations: 4 }),
  } as unknown as ConfigService<AppConfig, true>;
  const originals = {
    getScannable: vi.fn(async () => ({ id: 'od-1', domain: 'example.com' })),
  } as unknown as OriginalDomainsQuery;

  function make(status: string, perms: number, options: object = {}) {
    const s = scans(status, options);
    const fuzzer = {
      generate: vi.fn(() =>
        Array.from({ length: perms }, (_, i) => ({
          domain: `d${i}.com`,
          fuzzer: 'omission',
        })),
      ),
    } as unknown as FuzzerService;
    const ctQuery = {
      ctDomains: vi.fn(async (): Promise<[string, string][]> => []),
    };
    const flow = { add: vi.fn(async () => ({})) } as unknown as FlowProducer & {
      add: ReturnType<typeof vi.fn>;
    };
    return {
      s,
      fuzzer,
      flow,
      p: new ScanOrchestratorProcessor(
        s as unknown as ScansService,
        fuzzer,
        originals,
        ctQuery as never,
        flow,
        config,
      ),
      ctQuery,
    };
  }

  it('moves QUEUED → FUZZING → RESOLVING and adds one flow with a child per batch', async () => {
    const { s, flow, p, fuzzer } = make('QUEUED', 3, { fuzzers: ['omission'] });
    expect(await p.process(job({ scanId: 'scan-1' }))).toEqual({
      permutations: 3,
      batches: 2,
    });
    expect(fuzzer.generate).toHaveBeenCalledWith('example.com', {
      fuzzers: ['omission'],
    });
    expect(s.startResolving).toHaveBeenCalledWith('scan-1', 3);
    const tree = flow.add.mock.calls[0][0];
    expect(tree).toMatchObject({
      queueName: 'scan-finalize',
      opts: { jobId: 'finalize-scan-1' },
    });
    expect(tree.children).toHaveLength(2);
    expect(tree.children[1]).toMatchObject({
      queueName: 'dns-resolve',
      data: { batchIndex: 1, permutations: [['d2.com', 'omission']] },
      opts: { jobId: 'resolve-scan-1-1', ignoreDependencyOnFailure: true },
    });
  });

  it('full scans also re-resolve CT-found look-alikes (deduplicated); subset scans do not', async () => {
    const full = make('QUEUED', 1);
    full.ctQuery.ctDomains.mockResolvedValueOnce([
      ['paypal-secure-login.com', 'ct:combo'],
      ['d0.com', 'ct:typo'], // also a permutation → resolved once
    ]);
    await full.p.process(job({ scanId: 'scan-1' }));
    expect(full.ctQuery.ctDomains).toHaveBeenCalledWith('od-1');
    expect(full.s.startResolving).toHaveBeenCalledWith('scan-1', 2);
    expect(
      full.flow.add.mock.calls[0][0].children[0].data.permutations,
    ).toEqual([
      ['d0.com', 'omission'],
      ['paypal-secure-login.com', 'ct:combo'],
    ]);

    const subset = make('QUEUED', 1, { fuzzers: ['omission'] });
    await subset.p.process(job({ scanId: 'scan-2' }));
    expect(subset.ctQuery.ctDomains).not.toHaveBeenCalled();
  });

  it('re-adds the flow idempotently when retried after RESOLVING', async () => {
    const { s, flow, p } = make('RESOLVING', 1);
    await p.process(job({ scanId: 'scan-1' }));
    expect(s.startResolving).not.toHaveBeenCalled();
    expect(flow.add).toHaveBeenCalledOnce();
  });

  it('skips cancelled scans', async () => {
    const { flow, p } = make('CANCELLED', 1);
    expect(await p.process(job({ scanId: 'scan-1' }))).toEqual({
      skipped: 'scan is CANCELLED',
    });
    expect(flow.add).not.toHaveBeenCalled();
  });

  it('fails scans above the permutation cap and completes empty ones', async () => {
    const big = make('FUZZING', 5);
    await big.p.process(job({ scanId: 'scan-1' }));
    expect(big.s.fail).toHaveBeenCalledWith(
      'scan-1',
      expect.stringContaining('SCAN_MAX_PERMUTATIONS'),
    );

    const empty = make('FUZZING', 0);
    expect(await empty.p.process(job({ scanId: 'scan-1' }))).toEqual({
      permutations: 0,
      batches: 0,
    });
    expect(empty.s.complete).toHaveBeenCalled();
  });

  it('fails the scan only after the final attempt', async () => {
    const { s, p } = make('QUEUED', 1);
    await p.onFailed(
      job({ scanId: 'scan-1' }, { attemptsMade: 1 }),
      new Error('x'),
    );
    expect(s.fail).not.toHaveBeenCalled();
    await p.onFailed(
      job({ scanId: 'scan-1' }, { attemptsMade: 3 }),
      new Error('boom'),
    );
    expect(s.fail).toHaveBeenCalledWith('scan-1', 'Orchestration failed: boom');
  });
});

describe('DnsResolveProcessor', () => {
  const data = {
    scanId: 'scan-1',
    originalDomainId: 'od-1',
    batchIndex: 0,
    permutations: [
      ['a.com', 'omission'],
      ['b.com', 'addition'],
    ] as [string, string][],
  };

  it('resolves, awaits persistence via emitAsync, then records progress', async () => {
    const s = scans('RESOLVING');
    const dns = {
      resolveMany: vi.fn(async () => [
        { domain: 'a.com', registered: true },
        { domain: 'b.com', registered: false },
      ]),
    } as unknown as DnsResolverService;
    const events = new EventEmitter2();
    const order: string[] = [];
    events.on(SCAN_EVENTS.BATCH_RESOLVED, async (e) => {
      order.push(
        `persist:${e.resolutions.length}:${e.fuzzerByDomain['b.com']}`,
      );
    });
    s.recordProgress.mockImplementation(async () => {
      order.push('progress');
    });
    const p = new DnsResolveProcessor(
      dns,
      s as unknown as ScansService,
      events,
    );
    expect(await p.process(job(data))).toEqual({ resolved: 2, registered: 1 });
    expect(order).toEqual(['persist:1:addition', 'progress']);
  });

  it('passes the scan’s enrichment options to the persistence event', async () => {
    const s = scans('RESOLVING', { includeWhois: false });
    const dns = {
      resolveMany: vi.fn(async () => []),
    } as unknown as DnsResolverService;
    const events = new EventEmitter2();
    const seen = vi.fn();
    events.on(SCAN_EVENTS.BATCH_RESOLVED, seen);
    await new DnsResolveProcessor(
      dns,
      s as unknown as ScansService,
      events,
    ).process(job(data));
    expect(seen.mock.calls[0][0].enrichment).toEqual({
      whois: false,
      screenshots: true,
    });
  });

  it('fails the job (for retry) when persistence fails, without counting progress', async () => {
    const s = scans('RESOLVING');
    const dns = {
      resolveMany: vi.fn(async () => []),
    } as unknown as DnsResolverService;
    const events = new EventEmitter2();
    events.on(SCAN_EVENTS.BATCH_RESOLVED, async () => {
      throw new Error('db down');
    });
    await expect(
      new DnsResolveProcessor(
        dns,
        s as unknown as ScansService,
        events,
      ).process(job(data)),
    ).rejects.toThrow('db down');
    expect(s.recordProgress).not.toHaveBeenCalled();
  });

  it('skips batches of cancelled scans', async () => {
    const dns = { resolveMany: vi.fn() } as unknown as DnsResolverService;
    const p = new DnsResolveProcessor(
      dns,
      scans('CANCELLED') as unknown as ScansService,
      new EventEmitter2(),
    );
    expect(await p.process(job(data))).toEqual({
      skipped: 'scan is CANCELLED',
    });
    expect(dns.resolveMany).not.toHaveBeenCalled();
  });
});

describe('ScanFinalizeProcessor', () => {
  const counts = {
    countsForScan: vi.fn(async () => ({ registeredCount: 7, newCount: 2 })),
  } as unknown as ScannedDomainsQuery;
  const finalizeJob = (failures: Record<string, string>) =>
    Object.assign(
      job({ scanId: 'scan-1', batchSize: 500, permutationsTotal: 1200 }),
      {
        getIgnoredChildrenFailures: vi.fn(async () => failures),
      },
    );

  it('computes batch sizes including the partial tail', () => {
    expect([0, 1, 2, 3].map((i) => batchSizeAt(i, 500, 1200))).toEqual([
      500, 500, 200, 0,
    ]);
  });

  it('completes with DB-derived counts and the size of failed batches', async () => {
    const s = scans('RESOLVING');
    const p = new ScanFinalizeProcessor(s as unknown as ScansService, counts);
    await p.process(
      finalizeJob({ 'bull:dns-resolve:resolve-scan-1-2': 'timeout' }),
    );
    expect(s.complete).toHaveBeenCalledWith('scan-1', {
      registeredCount: 7,
      newCount: 2,
      failedCount: 200,
    });
  });

  it('fails the scan when every batch failed', async () => {
    const s = scans('RESOLVING');
    const p = new ScanFinalizeProcessor(s as unknown as ScansService, counts);
    await p.process(
      finalizeJob({
        'k:resolve-scan-1-0': 'x',
        'k:resolve-scan-1-1': 'x',
        'k:resolve-scan-1-2': 'x',
      }),
    );
    expect(s.fail).toHaveBeenCalledWith(
      'scan-1',
      expect.stringContaining('All 3 DNS batches failed'),
    );
  });

  it('does nothing for cancelled scans; fails the scan after the last attempt', async () => {
    const s = scans('CANCELLED');
    const p = new ScanFinalizeProcessor(s as unknown as ScansService, counts);
    expect(await p.process(finalizeJob({}))).toEqual({
      skipped: 'scan is CANCELLED',
    });
    await p.onFailed(
      job(
        { scanId: 'scan-1', batchSize: 1, permutationsTotal: 1 },
        { attemptsMade: 3 },
      ),
      new Error('x'),
    );
    expect(s.fail).toHaveBeenCalledWith('scan-1', 'Finalisation failed: x');
  });
});

describe('ScheduledScanProcessor', () => {
  it('creates a SCHEDULE-triggered scan', async () => {
    const s = scans();
    s.create.mockResolvedValue({
      scan: { id: 'scan-9', status: 'QUEUED' },
      created: true,
    });
    expect(
      await new ScheduledScanProcessor(s as unknown as ScansService).process(
        job({ originalDomainId: 'od-1' }),
      ),
    ).toEqual({
      scanId: 'scan-9',
      created: true,
    });
    expect(s.create).toHaveBeenCalledWith({
      originalDomainId: 'od-1',
      triggeredBy: 'SCHEDULE',
    });
  });

  it('treats client errors (deleted/inactive domain) as non-retryable skips, rethrows the rest', async () => {
    const s = scans();
    const p = new ScheduledScanProcessor(s as unknown as ScansService);
    s.create.mockRejectedValueOnce(new NotFoundException('gone'));
    expect(await p.process(job({ originalDomainId: 'od-1' }))).toEqual({
      skipped: 'gone',
    });
    s.create.mockRejectedValueOnce(new HttpException('oops', 503));
    await expect(p.process(job({ originalDomainId: 'od-1' }))).rejects.toThrow(
      'oops',
    );
  });
});
