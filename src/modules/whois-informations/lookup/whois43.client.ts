import { readFileSync } from 'node:fs';
import { createConnection } from 'node:net';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../../config/configuration.js';
import {
  isDomainNotFound,
  isRateLimited,
  isValidDomainResponse,
  registrarReferral,
} from './whois-text.js';

const IANA = 'whois.iana.org';
const RATE_LIMIT_RETRIES = 2;
const RATE_LIMIT_BACKOFF_MS = 5_000;

export type Whois43Outcome =
  | { kind: 'found'; text: string; server: string }
  | { kind: 'not_found'; text: string; server: string }
  | { kind: 'rate_limited'; server: string }
  | { kind: 'error'; message: string };

/** TLD → registry WHOIS server, from Reporting's config/whois_server.json (495 TLDs). */
function loadServerMap(): Map<string, string> {
  const file = new URL('../data/whois_server.json', import.meta.url);
  const json = JSON.parse(readFileSync(file, 'utf8')) as {
    whois_servers: Record<string, string>;
  };
  return new Map(
    Object.entries(json.whois_servers).map(([tld, server]) => [
      tld.toLowerCase(),
      server,
    ]),
  );
}

/**
 * Port-43 WHOIS (fallback when RDAP is unavailable), following Reporting's behaviour:
 * known server map → IANA referral for unknown TLDs, registry-throttling detection with
 * backoff, "not found" treated as definitive. Additionally follows the
 * "Registrar WHOIS Server" referral once to get the thick record for thin registries.
 */
@Injectable()
export class Whois43Client {
  private readonly logger = new Logger(Whois43Client.name);
  private readonly servers = loadServerMap();

  constructor(private readonly config: ConfigService<AppConfig, true>) {}

  async lookup(registrable: string): Promise<Whois43Outcome> {
    const tld = registrable.split('.').slice(1).join('.');
    const lastLabel = registrable.split('.').pop()!;
    const server =
      this.servers.get(tld) ??
      this.servers.get(lastLabel) ??
      (await this.discoverViaIana(lastLabel));
    if (!server)
      return {
        kind: 'error',
        message: `No WHOIS server known for .${lastLabel}`,
      };

    const registry = await this.queryWithBackoff(registrable, server);
    if (registry.kind !== 'found') return registry;

    const referral = registrarReferral(registry.text);
    if (referral && referral !== server) {
      const thick = await this.queryWithBackoff(registrable, referral);
      if (thick.kind === 'found') return thick;
    }
    return registry;
  }

  private async queryWithBackoff(
    domain: string,
    server: string,
  ): Promise<Whois43Outcome> {
    for (let attempt = 0; attempt <= RATE_LIMIT_RETRIES; attempt++) {
      let text: string | null;
      try {
        text = await this.raw(domain, server);
      } catch (e) {
        return {
          kind: 'error',
          message: `WHOIS ${server}: ${(e as Error).message}`,
        };
      }
      if (!text)
        return { kind: 'error', message: `WHOIS ${server}: empty response` };
      if (isRateLimited(text)) {
        if (attempt < RATE_LIMIT_RETRIES)
          await new Promise((r) => setTimeout(r, RATE_LIMIT_BACKOFF_MS));
        continue;
      }
      if (isDomainNotFound(text)) return { kind: 'not_found', text, server };
      if (isValidDomainResponse(text)) return { kind: 'found', text, server };
      return {
        kind: 'error',
        message: `WHOIS ${server}: unrecognised response`,
      };
    }
    this.logger.warn(
      `WHOIS ${server} still rate-limited after ${RATE_LIMIT_RETRIES} retries`,
    );
    return { kind: 'rate_limited', server };
  }

  private async discoverViaIana(tld: string): Promise<string | undefined> {
    try {
      const text = await this.raw(tld, IANA);
      const server = text
        ?.match(/^whois:\s+([-.a-z0-9]+\.[-.a-z0-9]+)/im)?.[1]
        .toLowerCase();
      if (server) this.servers.set(tld, server);
      return server;
    } catch {
      return undefined;
    }
  }

  /** One request/response over TCP 43 (the protocol: send query + CRLF, read until close). */
  raw(query: string, server: string): Promise<string | null> {
    const timeoutMs = this.config.get('enrichment', {
      infer: true,
    }).whoisTimeoutMs;
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      const socket = createConnection({ host: server, port: 43 });
      socket.setTimeout(timeoutMs);
      socket.on('connect', () => socket.write(`${query}\r\n`));
      socket.on('data', (chunk: Buffer) => chunks.push(chunk));
      socket.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve(text.length ? text : null);
      });
      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('timeout'));
      });
      socket.on('error', (e) => {
        socket.destroy();
        reject(e);
      });
    });
  }
}
