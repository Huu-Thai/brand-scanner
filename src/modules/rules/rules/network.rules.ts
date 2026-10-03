import { Resolver } from 'node:dns/promises';
import * as tls from 'node:tls';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../../config/configuration.js';
import { ReputationService } from '../../../integrations/threat-feed/reputation.service.js';
import { BaseRule } from '../base-rule.js';
import {
  type RuleConditionResolution,
  type RuleConfigRecord,
  type RuleEvaluationInput,
  RuleKey,
} from '../rule.types.js';

/** Rules that perform their own network lookups. Each fails soft (no points) on network errors. */

function resolverFor(config: ConfigService<AppConfig, true>): Resolver {
  const timeout = config.get('enrichment', {
    infer: true,
  }).ruleNetworkTimeoutMs;
  const resolver = new Resolver({ timeout, tries: 2 });
  const { nameservers } = config.get('dns', { infer: true });
  if (nameservers.length) resolver.setServers(nameservers);
  return resolver;
}

export type DmarcPolicy = 'missing' | 'none' | 'quarantine' | 'reject';

/** `_dmarc.<domain>` p= policy; no/invalid record counts as "missing" (Reporting semantics). */
@Injectable()
export class DmarcMissingRule extends BaseRule {
  readonly key = RuleKey.DMARC_MISSING;
  constructor(private readonly config: ConfigService<AppConfig, true>) {
    super();
  }

  protected async resolveCondition(
    input: RuleEvaluationInput,
  ): Promise<RuleConditionResolution> {
    const policy = await this.checkDmarc(input.fuzzerDomain);
    return { condition: policy, value: policy };
  }

  async checkDmarc(domain: string): Promise<DmarcPolicy> {
    try {
      return (
        extractDmarcPolicy(
          await resolverFor(this.config).resolveTxt(`_dmarc.${domain}`),
        ) ?? 'missing'
      );
    } catch {
      return 'missing';
    }
  }
}

/** TXT records are split into 255-byte chunks; rejoin, find v=DMARC1, read p=. */
export function extractDmarcPolicy(records: string[][]): DmarcPolicy | null {
  for (const chunks of records) {
    const record = chunks.join('').trim();
    if (!/^v=DMARC1/i.test(record)) continue;
    const match = record.match(/;\s*p\s*=\s*(none|quarantine|reject)\b/i);
    if (match) return match[1].toLowerCase() as DmarcPolicy;
  }
  return null;
}

/**
 * First A record on Spamhaus ZEN. Unlike Reporting, only real listing codes (127.0.0.x)
 * count: Spamhaus answers 127.255.255.x when it refuses a query (e.g. via public
 * resolvers), which must not be mistaken for a listing.
 */
@Injectable()
export class SpamhausBlacklistRule extends BaseRule {
  readonly key = RuleKey.SPAMHAUS_BLACKLIST;
  constructor(private readonly config: ConfigService<AppConfig, true>) {
    super();
  }

  protected async resolveCondition(
    input: RuleEvaluationInput,
  ): Promise<RuleConditionResolution | null> {
    const ip = input.dns?.a[0];
    if (!ip) return { condition: 'default', value: 'not listed' };
    const result = await this.lookup(ip);
    if (result.status === 'refused') return null; // unknown — no points either way
    return result.status === 'listed'
      ? { condition: 'listed', value: result.code }
      : { condition: 'default', value: 'not listed' };
  }

  async lookup(
    ip: string,
  ): Promise<
    | { status: 'listed'; code: string }
    | { status: 'clean' }
    | { status: 'refused' }
  > {
    const reversed = ip.split('.').reverse().join('.');
    try {
      const answers = await resolverFor(this.config).resolve4(
        `${reversed}.zen.spamhaus.org`,
      );
      return interpretSpamhaus(answers);
    } catch {
      return { status: 'clean' }; // NXDOMAIN = not listed; other failures fail soft
    }
  }
}

export function interpretSpamhaus(answers: string[]) {
  const listing = answers.find((a) => /^127\.0\.0\.(\d+)$/.test(a));
  if (listing) return { status: 'listed' as const, code: listing };
  if (answers.some((a) => a.startsWith('127.255.255.')))
    return { status: 'refused' as const };
  return { status: 'clean' as const };
}

export interface SslCheckResult {
  hasHttps: boolean;
  isValid: boolean;
  isExpired: boolean;
  isSelfSigned: boolean;
  isUntrusted: boolean;
}

/** TLS handshake on :443 with verification off so the certificate can always be inspected. */
@Injectable()
export class SslIssuesRule extends BaseRule {
  readonly key = RuleKey.SSL_ISSUES;
  constructor(private readonly config: ConfigService<AppConfig, true>) {
    super();
  }

  protected async resolveCondition(
    input: RuleEvaluationInput,
    config: RuleConfigRecord,
  ): Promise<RuleConditionResolution> {
    const trusted = Array.isArray(config.params.ca_issuers)
      ? (config.params.ca_issuers as unknown[]).filter(
          (i): i is string => typeof i === 'string',
        )
      : [];
    // Connect to the address the pipeline resolved (same nameserver pool as everything else);
    // SNI still carries the hostname. A domain that resolved to nothing cannot serve HTTPS.
    const address = input.dns
      ? (input.dns.a[0] ?? input.dns.aaaa[0])
      : undefined;
    if (input.dns && !address)
      return { condition: 'missing', value: 'no address' };
    const ssl = await this.check(input.fuzzerDomain, trusted, 443, address);
    if (!ssl.hasHttps) return { condition: 'missing', value: 'no HTTPS' };
    if (ssl.isExpired) return { condition: 'expired', value: 'expired' };
    if (ssl.isSelfSigned)
      return { condition: 'self-signed', value: 'self-signed' };
    if (ssl.isUntrusted) return { condition: 'untrusted', value: 'untrusted' };
    if (!ssl.isValid) return { condition: 'invalid', value: 'invalid' };
    return { condition: 'default', value: 'valid' };
  }

  check(
    hostname: string,
    trustedIssuers: string[],
    port = 443,
    address?: string,
  ): Promise<SslCheckResult> {
    const timeout = this.config.get('enrichment', {
      infer: true,
    }).ruleNetworkTimeoutMs;
    return new Promise((resolve) => {
      const result: SslCheckResult = {
        hasHttps: false,
        isValid: false,
        isExpired: false,
        isSelfSigned: false,
        isUntrusted: false,
      };
      let socket: tls.TLSSocket | undefined;
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket?.destroy();
        resolve(result);
      };
      const timer = setTimeout(finish, timeout);
      try {
        socket = tls.connect(
          {
            host: address ?? hostname,
            port,
            servername: hostname,
            rejectUnauthorized: false,
          },
          () => {
            const cert = socket!.getPeerCertificate();
            if (cert && Object.keys(cert).length > 0) {
              result.hasHttps = true;
              result.isValid = socket!.authorized;
              const code = authorizationErrorCode(socket!.authorizationError);
              result.isSelfSigned =
                code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
                code === 'SELF_SIGNED_CERT_IN_CHAIN';
              result.isExpired =
                code === 'CERT_HAS_EXPIRED' ||
                (cert.valid_to
                  ? new Date(cert.valid_to).getTime() < Date.now()
                  : false);
              const issuer = Array.isArray(cert.issuer?.O)
                ? cert.issuer.O[0]
                : cert.issuer?.O;
              const knownIssuer = trustedIssuers.length
                ? typeof issuer === 'string' && trustedIssuers.includes(issuer)
                : true;
              result.isUntrusted =
                !result.isSelfSigned &&
                (code === 'UNABLE_TO_GET_ISSUER_CERT' ||
                  code === 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY' ||
                  code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
                  !knownIssuer);
            }
            finish();
          },
        );
        socket.on('error', finish);
      } catch {
        finish();
      }
    });
  }
}

/**
 * At runtime Node sets `TLSSocket.authorizationError` to the OpenSSL code as a plain string
 * (e.g. "DEPTH_ZERO_SELF_SIGNED_CERT") although @types/node declares `Error`. Reporting read
 * `.code`/`.message`, which are undefined on a string, so certificate problems were never seen.
 */
export function authorizationErrorCode(err: unknown): string | undefined {
  if (!err) return undefined;
  if (typeof err === 'string') return err;
  return (err as NodeJS.ErrnoException).code ?? (err as Error).message;
}

/**
 * Active indicator in manage-feed (threat-feed API): the look-alike as a DOMAIN, or its first
 * A record as an IPV4. Unknown (integration disabled/unreachable) → no points.
 */
@Injectable()
export class ReputationCheckRule extends BaseRule {
  readonly key = RuleKey.REPUTATION_CHECK;
  constructor(private readonly reputation: ReputationService) {
    super();
  }

  protected async resolveCondition(
    input: RuleEvaluationInput,
  ): Promise<RuleConditionResolution> {
    const verdict = await this.reputation.check(
      input.fuzzerDomain,
      input.dns?.a[0],
    );
    if (verdict.status === 'found') {
      return {
        condition: 'found',
        value: `manage-feed ${verdict.indicatorType} ${verdict.value}`,
      };
    }
    return {
      condition: 'default',
      value:
        verdict.status === 'unknown'
          ? `unknown: ${verdict.reason}`
          : 'not found',
    };
  }
}
