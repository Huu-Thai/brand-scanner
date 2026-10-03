import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../../config/configuration.js';
import { HostRateLimiter } from './rate-limiter.js';
import { parseRdap, type RdapDomain } from './rdap.parser.js';
import type { WhoisRecord } from './whois.types.js';

/** Longest a lookup waits for a registry's rate window before handing the slot back. */
export const HOST_BUSY_MAX_WAIT_MS = 1_000;

export const DEFAULT_RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000;

export type RdapOutcome =
  | { kind: 'found'; record: WhoisRecord; raw: string }
  | { kind: 'not_found' }
  | { kind: 'unsupported' } // TLD has no RDAP service in the IANA bootstrap
  | { kind: 'error'; message: string };

/** RDAP (RFC 9082/9083) via the IANA bootstrap registry. */
@Injectable()
export class RdapClient {
  private readonly logger = new Logger(RdapClient.name);
  private readonly limiter = new HostRateLimiter();
  private bootstrap?: { loadedAt: number; byTld: Map<string, string> };

  constructor(private readonly config: ConfigService<AppConfig, true>) {}

  async lookup(registrable: string): Promise<RdapOutcome> {
    const tld = registrable.split('.').pop()!;
    let base: string | undefined;
    try {
      base = await this.baseUrlFor(tld);
    } catch (e) {
      return {
        kind: 'error',
        message: `RDAP bootstrap unavailable: ${(e as Error).message}`,
      };
    }
    if (!base) return { kind: 'unsupported' };

    const url = `${base.replace(/\/+$/, '')}/domain/${registrable}`;
    const host = new URL(url).host;
    // Never sleep long inside a job: a busy registry raises HostBusyError (→ delayed job).
    return this.limiter.run(
      host,
      async () => {
        try {
          const res = await fetch(url, {
            headers: { accept: 'application/rdap+json, application/json' },
            redirect: 'follow',
            signal: AbortSignal.timeout(
              this.config.get('enrichment', { infer: true }).whoisTimeoutMs,
            ),
          });
          if (res.status === 404) return { kind: 'not_found' };
          if (!res.ok)
            return {
              kind: 'error',
              message: `RDAP ${host} → HTTP ${res.status}`,
            };
          const raw = await res.text();
          return {
            kind: 'found',
            record: parseRdap(JSON.parse(raw) as RdapDomain),
            raw,
          };
        } catch (e) {
          return {
            kind: 'error',
            message: `RDAP ${host}: ${(e as Error).message}`,
          };
        }
      },
      HOST_BUSY_MAX_WAIT_MS,
    );
  }

  private async baseUrlFor(tld: string): Promise<string | undefined> {
    if (
      !this.bootstrap ||
      Date.now() - this.bootstrap.loadedAt > BOOTSTRAP_TTL_MS
    ) {
      const res = await fetch(
        this.config.get('enrichment', { infer: true }).rdapBootstrapUrl,
        {
          signal: AbortSignal.timeout(10_000),
        },
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = (await res.json()) as { services: [string[], string[]][] };
      const byTld = new Map<string, string>();
      for (const [tlds, urls] of json.services) {
        const url = urls.find((u) => u.startsWith('https://')) ?? urls[0];
        for (const t of tlds) byTld.set(t.toLowerCase(), url);
      }
      this.bootstrap = { loadedAt: Date.now(), byTld };
      this.logger.log(`RDAP bootstrap loaded (${byTld.size} TLDs)`);
    }
    return this.bootstrap.byTld.get(tld.toLowerCase());
  }
}
