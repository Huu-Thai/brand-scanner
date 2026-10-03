import { dnsLookupDuration } from '../../metrics/metrics.js';
import { Resolver } from 'node:dns/promises';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { mapWithConcurrency } from '../../common/utils/concurrency.js';
import type { AppConfig } from '../../config/configuration.js';
import type {
  DnsErrorCode,
  DnsOutcomeKind,
  DnsResolution,
  Resolvable,
} from './dns.types.js';

/** Nameservers queried concurrently within one failover pass (Reporting: DNS_BATCH_SIZE). */
const NAMESERVER_BATCH = 3;
const SERVFAIL = '!ServFail';

export function classifyDnsError(code: string | undefined): DnsOutcomeKind {
  switch (code) {
    case 'ENOTFOUND':
      return 'nxdomain';
    case 'ENODATA':
      return 'noanswer';
    case 'ESERVFAIL':
    case 'EREFUSED':
    case 'ECONNREFUSED':
      return 'servfail';
    case 'ETIMEOUT':
      return 'timeout';
    default:
      return 'error';
  }
}

/**
 * Registration check for permutations, ported from Reporting's DnstwistService so results
 * match production:
 *  - one c-ares resolver per nameserver (c-ares does not reliably fail over itself);
 *  - NS first — NXDOMAIN is definitive and skips A/AAAA/MX (the overwhelmingly common case);
 *  - each lookup fails over past SERVFAIL/REFUSED/timeout, rotating the starting server;
 *  - only whole-pass timeouts are retried (with backoff).
 */
@Injectable()
export class DnsResolverService {
  private readonly resolvers: Resolvable[];
  private readonly retries: number;
  private readonly concurrency: number;
  private rotation = 0;

  constructor(
    config: ConfigService<AppConfig, true>,
    resolvers?: Resolvable[],
  ) {
    const dns = config.get('dns', { infer: true });
    this.retries = dns.retries;
    this.concurrency = dns.concurrency;
    this.resolvers =
      resolvers ??
      dns.nameservers.map((server) => {
        const resolver = new Resolver({ timeout: dns.timeoutMs, tries: 1 });
        resolver.setServers([server]);
        return resolver;
      });
  }

  resolveMany(domains: readonly string[]): Promise<DnsResolution[]> {
    return mapWithConcurrency(domains, this.concurrency, (domain) =>
      this.resolve(domain),
    );
  }

  async resolve(domain: string): Promise<DnsResolution> {
    const end = dnsLookupDuration.startTimer();
    const result = await this.resolveOnce(domain);
    end({
      outcome: result.nxdomain
        ? 'nxdomain'
        : result.registered
          ? 'registered'
          : result.errors.length
            ? 'error'
            : 'empty',
    });
    return result;
  }

  private async resolveOnce(domain: string): Promise<DnsResolution> {
    const errors: DnsErrorCode[] = [];
    const result: DnsResolution = {
      domain,
      nxdomain: false,
      registered: false,
      a: [],
      aaaa: [],
      mx: [],
      ns: [],
      ttl: null,
      errors,
    };

    const failure = (kind: DnsOutcomeKind): string[] => {
      if (kind === 'servfail') {
        errors.push('NO_NAMESERVERS');
        return [SERVFAIL];
      }
      if (kind === 'timeout') errors.push('TIMEOUT');
      else if (kind === 'error') errors.push('DNS_EXCEPTION');
      return [];
    };

    // 1) NS gates everything else.
    const ns = await this.failover((r) => r.resolveNs(domain));
    let nsServfail = false;
    let nsResolved = false;
    if (ns.kind === 'ok' || ns.kind === 'noanswer') {
      result.ns = ns.list;
      nsResolved = true;
    } else if (ns.kind === 'nxdomain') {
      result.nxdomain = true;
      return result;
    } else {
      nsServfail = failure(ns.kind).length > 0;
    }

    // 2) A, AAAA and (NS-gated) MX. Soft NODATA: the name exists, so one server's NODATA may be stale.
    const ttls: number[] = [];
    const tasks: Promise<void>[] = [
      this.failover((r) => r.resolve4(domain, { ttl: true }), true).then(
        (r) => {
          if (r.kind === 'ok') {
            result.a = r.list.map((x) => x.address);
            ttls.push(...r.list.map((x) => x.ttl));
          } else failure(r.kind);
        },
      ),
      this.failover((r) => r.resolve6(domain, { ttl: true }), true).then(
        (r) => {
          if (r.kind === 'ok') {
            result.aaaa = r.list.map((x) => x.address);
            ttls.push(...r.list.map((x) => x.ttl));
          } else failure(r.kind);
        },
      ),
    ];
    if (nsResolved) {
      tasks.push(
        this.failover((r) => r.resolveMx(domain), true).then((r) => {
          if (r.kind === 'ok') {
            result.mx = [...r.list]
              .sort((x, y) => x.priority - y.priority)
              .map((m) => m.exchange);
          } else failure(r.kind);
        }),
      );
    }
    await Promise.all(tasks);

    result.ttl = ttls.length ? Math.min(...ttls) : null;
    result.errors = [...new Set(errors)];
    result.registered =
      nsServfail ||
      result.ns.length > 0 ||
      result.a.length > 0 ||
      result.aaaa.length > 0 ||
      result.mx.length > 0;
    return result;
  }

  private async failover<T>(
    pick: (r: Resolvable) => Promise<T[]>,
    softNoanswer = false,
  ): Promise<{ kind: DnsOutcomeKind; list: T[] }> {
    for (let attempt = 0; ; attempt++) {
      const res = await this.failoverOnce(pick, softNoanswer);
      if (res.kind !== 'timeout' || attempt >= this.retries) return res;
      await new Promise((resolve) => setTimeout(resolve, 500 * 2 ** attempt));
    }
  }

  private async failoverOnce<T>(
    pick: (r: Resolvable) => Promise<T[]>,
    softNoanswer: boolean,
  ): Promise<{ kind: DnsOutcomeKind; list: T[] }> {
    const n = this.resolvers.length;
    const start = n > 0 ? this.rotation++ % n : 0;
    const rotated = Array.from(
      { length: n },
      (_, i) => this.resolvers[(start + i) % n],
    );
    const maxSoft = Math.max(3, Math.ceil(n / 2));

    let lastHard: DnsOutcomeKind = 'servfail';
    let sawTimeout = false;
    let sawNoanswer = false;
    let consecutiveNoanswer = 0;
    let servfails = 0;

    for (let i = 0; i < n; i += NAMESERVER_BATCH) {
      const settled = await Promise.allSettled(
        rotated.slice(i, i + NAMESERVER_BATCH).map(pick),
      );
      for (const outcome of settled) {
        if (outcome.status === 'fulfilled')
          return { kind: 'ok', list: outcome.value };
        const kind = classifyDnsError(
          (outcome.reason as NodeJS.ErrnoException)?.code,
        );

        if (kind === 'nxdomain' || kind === 'noanswer') {
          if (!softNoanswer) return { kind, list: [] };
          // Soft mode: c-ares reports ENOTFOUND for both "no such name" and "no record of this
          // type" on A/AAAA; NS already proved the name exists, so keep asking a few servers.
          sawNoanswer = true;
          if (++consecutiveNoanswer >= maxSoft)
            return { kind: 'noanswer', list: [] };
          continue;
        }
        consecutiveNoanswer = 0;
        if (kind === 'timeout') sawTimeout = true;
        if (kind === 'servfail') servfails++;
        lastHard = kind;
      }
    }
    if (sawNoanswer) return { kind: 'noanswer', list: [] };
    if (servfails > 0) return { kind: 'servfail', list: [] };
    return { kind: sawTimeout ? 'timeout' : lastHard, list: [] };
  }
}
