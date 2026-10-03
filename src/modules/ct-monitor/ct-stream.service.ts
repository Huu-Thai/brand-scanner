import { randomUUID } from 'node:crypto';
import { InjectQueue } from '@nestjs/bullmq';
import {
  Inject,
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Queue } from 'bullmq';
import type { Redis } from 'ioredis';
import type { AppConfig } from '../../config/configuration.js';
import {
  ctCertificatesTotal,
  ctMatchesTotal,
  ctStreamConnected,
} from '../../metrics/metrics.js';
import { JOBS, type CtMatchJobData } from '../../queue/jobs.js';
import { QUEUES } from '../../queue/queue.constants.js';
import { REDIS_CLIENT } from '../../redis/redis.module.js';
import { OriginalDomainsQuery } from '../original-domains/original-domains.query.js';
import {
  brandTarget,
  matchCertificate,
  type BrandTarget,
} from './ct-matcher.js';

export const CT_LEADER_KEY = 'lock:ct-stream';
export const CT_STATS_KEY = 'ct:stats';
const LEASE_MS = 30_000;
const DEDUPE_TTL_S = 7 * 86_400;
const BRAND_REFRESH_MS = 60_000;
const RENEW = `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('pexpire', KEYS[1], ARGV[2]) else return 0 end`;
const RELEASE = `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end`;

/** The parts of a certstream message we use (full `certificate_update` or `/domains-only` `dns_entries`). */
export function namesFromMessage(raw: string): string[] | null {
  let msg: { message_type?: string; data?: unknown };
  try {
    msg = JSON.parse(raw) as typeof msg;
  } catch {
    return null;
  }
  if (msg.message_type === 'certificate_update') {
    const names = (msg.data as { leaf_cert?: { all_domains?: unknown } })
      ?.leaf_cert?.all_domains;
    return Array.isArray(names)
      ? names.filter((n): n is string => typeof n === 'string')
      : null;
  }
  if (msg.message_type === 'dns_entries' && Array.isArray(msg.data))
    return msg.data.filter((n): n is string => typeof n === 'string');
  return null; // heartbeat, unknown
}

/**
 * Consumes a Certificate Transparency stream and queues certificates that imitate a brand.
 * Exactly one process consumes (Redis leader lease, renewed every 10 s; another process takes
 * over within ~30 s if the leader dies). Matches are de-duplicated for 7 days per brand+domain.
 */
@Injectable()
export class CtStreamService
  implements OnApplicationBootstrap, OnApplicationShutdown
{
  private readonly logger = new Logger(CtStreamService.name);
  private readonly token = randomUUID();
  private leader = false;
  private socket?: WebSocket;
  private brands: BrandTarget[] = [];
  private brandsLoadedAt = 0;
  private electionTimer?: NodeJS.Timeout;
  private statsTimer?: NodeJS.Timeout;
  private stallTimer?: NodeJS.Timeout;
  private backoffMs = 1_000;
  private stopped = false;
  private pending = { certs: 0, matches: 0 };
  private lastMessageAt = 0;

  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    private readonly originalDomains: OriginalDomainsQuery,
    @InjectQueue(QUEUES.CT_MATCHES)
    private readonly queue: Queue<CtMatchJobData>,
    @Inject(REDIS_CLIENT) private readonly redis: Redis,
  ) {}

  private get settings() {
    return this.config.get('ct', { infer: true });
  }

  onApplicationBootstrap(): void {
    if (!this.settings.enabled) return;
    void this.elect();
    this.electionTimer = setInterval(() => void this.elect(), LEASE_MS / 3);
    this.statsTimer = setInterval(() => void this.flushStats(), 5_000);
    this.electionTimer.unref();
    this.statsTimer.unref();
  }

  async onApplicationShutdown(): Promise<void> {
    this.stopped = true;
    clearInterval(this.electionTimer);
    clearInterval(this.statsTimer);
    clearTimeout(this.stallTimer);
    this.socket?.close();
    ctStreamConnected.set(0);
    if (this.leader)
      await this.redis
        .eval(RELEASE, 1, CT_LEADER_KEY, this.token)
        .catch(() => undefined);
  }

  /** Acquire or renew the leader lease; connect when we become leader, disconnect if we lose it. */
  async elect(): Promise<boolean> {
    try {
      const was = this.leader;
      this.leader = was
        ? (await this.redis.eval(
            RENEW,
            1,
            CT_LEADER_KEY,
            this.token,
            String(LEASE_MS),
          )) === 1
        : (await this.redis.set(
            CT_LEADER_KEY,
            this.token,
            'PX',
            LEASE_MS,
            'NX',
          )) === 'OK';
      if (this.leader && !was) {
        this.logger.log('CT monitor: became leader, connecting');
        this.connect();
      } else if (!this.leader && was) {
        this.logger.warn('CT monitor: lost leadership, disconnecting');
        this.socket?.close();
      }
    } catch (e) {
      this.logger.warn(`CT leader election failed: ${(e as Error).message}`);
    }
    return this.leader;
  }

  private connect(): void {
    if (this.stopped || !this.leader) return;
    const url = this.settings.streamUrl;
    const ws = new WebSocket(url);
    this.socket = ws;
    ws.addEventListener('open', () => {
      this.backoffMs = 1_000;
      ctStreamConnected.set(1);
      this.lastMessageAt = Date.now();
      this.armWatchdog();
      void this.redis
        .hset(CT_STATS_KEY, { connectedSince: new Date().toISOString(), url })
        .catch(() => undefined);
      this.logger.log(`CT monitor: connected to ${url}`);
    });
    ws.addEventListener('message', (ev) => {
      this.lastMessageAt = Date.now();
      void this.handle(typeof ev.data === 'string' ? ev.data : '').catch(
        (e: Error) =>
          this.logger.warn(`CT message handling failed: ${e.message}`),
      );
    });
    ws.addEventListener('close', () => {
      ctStreamConnected.set(0);
      clearTimeout(this.stallTimer);
      if (this.socket !== ws || this.stopped || !this.leader) return;
      const wait = this.backoffMs;
      this.backoffMs = Math.min(this.backoffMs * 2, 60_000);
      this.logger.warn(`CT monitor: stream closed; reconnecting in ${wait} ms`);
      setTimeout(() => this.connect(), wait).unref();
    });
    ws.addEventListener('error', () => undefined); // 'close' follows and handles reconnection
  }

  private armWatchdog(): void {
    clearTimeout(this.stallTimer);
    const { stallTimeoutMs } = this.settings;
    this.stallTimer = setTimeout(() => {
      if (Date.now() - this.lastMessageAt >= stallTimeoutMs) {
        this.logger.warn(
          `CT monitor: no message for ${stallTimeoutMs} ms; reconnecting`,
        );
        this.socket?.close();
      } else this.armWatchdog();
    }, stallTimeoutMs);
    this.stallTimer.unref();
  }

  private async targets(): Promise<BrandTarget[]> {
    if (Date.now() - this.brandsLoadedAt > BRAND_REFRESH_MS) {
      this.brands = (await this.originalDomains.listActive())
        .map((b) => brandTarget(b.id, b.domain))
        .filter((b): b is BrandTarget => !!b);
      this.brandsLoadedAt = Date.now();
    }
    return this.brands;
  }

  /** One stream message → zero or more queued candidates. Public for tests. */
  async handle(raw: string): Promise<number> {
    const names = namesFromMessage(raw);
    if (!names?.length) return 0;
    this.pending.certs++;
    ctCertificatesTotal.inc();
    const brands = await this.targets();
    if (!brands.length) return 0;
    const { minKeywordLength, maxEditDistance } = this.settings;
    let queued = 0;
    for (const m of matchCertificate(names, brands, {
      minKeywordLength,
      maxEditDistance,
    })) {
      const fresh = await this.redis.set(
        `ct:seen:${m.originalDomainId}:${m.domain}`,
        '1',
        'EX',
        DEDUPE_TTL_S,
        'NX',
      );
      if (fresh !== 'OK') continue;
      await this.queue.add(
        JOBS.CT_MATCH,
        {
          originalDomainId: m.originalDomainId,
          domain: m.domain,
          certName: m.certName,
          kind: m.kind,
          seenAt: new Date().toISOString(),
        },
        {
          jobId: `ct-${m.originalDomainId}-${m.domain}`,
          attempts: 3,
          backoff: { type: 'exponential', delay: 60_000 },
          removeOnComplete: { age: 7 * 86_400, count: 10_000 },
          removeOnFail: { age: 7 * 86_400 },
        },
      );
      ctMatchesTotal.inc({ kind: m.kind });
      this.pending.matches++;
      queued++;
    }
    return queued;
  }

  private async flushStats(): Promise<void> {
    if (!this.leader) return;
    const { certs, matches } = this.pending;
    this.pending = { certs: 0, matches: 0 };
    await this.redis
      .multi()
      .hincrby(CT_STATS_KEY, 'certificates', certs)
      .hincrby(CT_STATS_KEY, 'matches', matches)
      .hset(CT_STATS_KEY, {
        leader: this.token,
        connected: this.socket?.readyState === WebSocket.OPEN ? '1' : '0',
        lastMessageAt: this.lastMessageAt
          ? new Date(this.lastMessageAt).toISOString()
          : '',
      })
      .exec()
      .catch(() => undefined);
  }
}
