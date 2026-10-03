import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../config/configuration.js';
import {
  classifyDnsError,
  DnsResolverService,
} from './dns-resolver.service.js';
import type { Resolvable } from './dns.types.js';

const err = (code: string) => Object.assign(new Error(code), { code });

type Records = Partial<{
  ns: string[] | string;
  a: { address: string; ttl: number }[] | string;
  aaaa: { address: string; ttl: number }[] | string;
  mx: { priority: number; exchange: string }[] | string;
}>;

/** A fake nameserver: each record type either answers or fails with an error code. */
function server(records: Records): Resolvable & { calls: string[] } {
  const calls: string[] = [];
  const answer = <T>(kind: string, value: T[] | string | undefined) => {
    calls.push(kind);
    if (value === undefined) return Promise.reject(err('ENODATA'));
    return typeof value === 'string'
      ? Promise.reject(err(value))
      : Promise.resolve(value);
  };
  return {
    calls,
    resolveNs: () => answer('ns', records.ns),
    resolve4: () => answer('a', records.a),
    resolve6: () => answer('aaaa', records.aaaa),
    resolveMx: () => answer('mx', records.mx),
  };
}

function service(resolvers: Resolvable[], retries = 0) {
  const config = {
    get: () => ({ nameservers: [], timeoutMs: 100, retries, concurrency: 5 }),
  } as unknown as ConfigService<AppConfig, true>;
  return new DnsResolverService(config, resolvers);
}

describe('classifyDnsError', () => {
  it.each([
    ['ENOTFOUND', 'nxdomain'],
    ['ENODATA', 'noanswer'],
    ['ESERVFAIL', 'servfail'],
    ['EREFUSED', 'servfail'],
    ['ETIMEOUT', 'timeout'],
    ['EWHATEVER', 'error'],
  ])('%s → %s', (code, kind) => expect(classifyDnsError(code)).toBe(kind));
});

describe('DnsResolverService', () => {
  it('stops at NXDOMAIN on NS without querying other record types', async () => {
    const ns = server({ ns: 'ENOTFOUND' });
    const r = await service([ns]).resolve('nope.example');
    expect(r).toMatchObject({
      nxdomain: true,
      registered: false,
      a: [],
      errors: [],
    });
    expect(ns.calls).toEqual(['ns']);
  });

  it('collects records, sorts MX by priority and keeps the lowest TTL', async () => {
    const r = await service([
      server({
        ns: ['ns1.x', 'ns2.x'],
        a: [{ address: '1.2.3.4', ttl: 600 }],
        aaaa: [{ address: '::1', ttl: 120 }],
        mx: [
          { priority: 20, exchange: 'mx2.x' },
          { priority: 10, exchange: 'mx1.x' },
        ],
      }),
    ]).resolve('exampel.com');
    expect(r).toMatchObject({
      registered: true,
      ns: ['ns1.x', 'ns2.x'],
      a: ['1.2.3.4'],
      aaaa: ['::1'],
      mx: ['mx1.x', 'mx2.x'],
      ttl: 120,
    });
  });

  it('fails over past SERVFAIL to a server that answers', async () => {
    const broken = server({
      ns: 'ESERVFAIL',
      a: 'ESERVFAIL',
      aaaa: 'ESERVFAIL',
      mx: 'ESERVFAIL',
    });
    const good = server({
      ns: ['ns1.x'],
      a: [{ address: '5.6.7.8', ttl: 300 }],
    });
    const r = await service([broken, broken, broken, good]).resolve(
      'exampel.com',
    );
    expect(r.a).toEqual(['5.6.7.8']);
    expect(r.errors).toEqual([]);
  });

  it('counts a SERVFAIL on NS everywhere as registered (lame delegation)', async () => {
    const r = await service([
      server({ ns: 'ESERVFAIL', a: 'ESERVFAIL', aaaa: 'ESERVFAIL' }),
    ]).resolve('lame.com');
    expect(r).toMatchObject({ nxdomain: false, registered: true, ns: [] });
    expect(r.errors).toEqual(['NO_NAMESERVERS']);
  });

  it('skips MX when NS failed, and reports timeouts without marking registered', async () => {
    const s = server({ ns: 'ETIMEOUT', a: 'ETIMEOUT', aaaa: 'ETIMEOUT' });
    const r = await service([s]).resolve('slow.com');
    expect(s.calls).not.toContain('mx');
    expect(r.registered).toBe(false);
    expect(r.errors).toEqual(['TIMEOUT']);
  });

  it('retries a pass that timed out, then succeeds', async () => {
    let first = true;
    const flaky: Resolvable = {
      resolveNs: () => {
        if (first) {
          first = false;
          return Promise.reject(err('ETIMEOUT'));
        }
        return Promise.resolve(['ns1.x']);
      },
      resolve4: () => Promise.reject(err('ENODATA')),
      resolve6: () => Promise.reject(err('ENODATA')),
      resolveMx: () => Promise.reject(err('ENODATA')),
    };
    vi.useFakeTimers();
    const pending = service([flaky], 1).resolve('retry.com');
    await vi.runAllTimersAsync();
    const r = await pending;
    vi.useRealTimers();
    expect(r).toMatchObject({ registered: true, ns: ['ns1.x'] });
  });

  it('treats NODATA on A as soft: keeps asking other servers before giving up', async () => {
    const stale = server({ ns: ['ns1.x'] }); // A → ENODATA
    const fresh = server({
      ns: ['ns1.x'],
      a: [{ address: '9.9.9.9', ttl: 60 }],
    });
    const r = await service([stale, stale, stale, fresh]).resolve(
      'exampel.com',
    );
    expect(r.a).toEqual(['9.9.9.9']);
  });

  it('rotates the starting nameserver between lookups', async () => {
    // 4 servers, 3 queried per pass, NXDOMAIN is definitive after the first pass:
    // lookup 1 hits servers 0-2, lookup 2 (rotated by one) hits servers 1-3.
    const servers = [0, 1, 2, 3].map(() => server({ ns: 'ENOTFOUND' }));
    const svc = service(servers);
    await svc.resolve('x1.com');
    await svc.resolve('x2.com');
    expect(servers.map((s) => s.calls.length)).toEqual([1, 2, 2, 1]);
  });

  it('builds one resolver per configured nameserver by default', () => {
    const config = {
      get: () => ({
        nameservers: ['1.1.1.1', '8.8.8.8'],
        timeoutMs: 1000,
        retries: 0,
        concurrency: 1,
      }),
    } as unknown as ConfigService<AppConfig, true>;
    expect(
      (new DnsResolverService(config) as unknown as { resolvers: unknown[] })
        .resolvers,
    ).toHaveLength(2);
  });
});
