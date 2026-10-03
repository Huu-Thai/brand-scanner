import { createServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../config/configuration.js';
import type { ReputationService } from '../../integrations/threat-feed/reputation.service.js';
import {
  DnsResolvesRule,
  DomainAgeRule,
  levenshtein,
  LevenshteinDistanceRule,
  LowTtlRule,
  MxRecordsFoundRule,
  SuspiciousTldRule,
} from './rules/local.rules.js';
import {
  DmarcMissingRule,
  extractDmarcPolicy,
  interpretSpamhaus,
  ReputationCheckRule,
  SpamhausBlacklistRule,
  SslIssuesRule,
} from './rules/network.rules.js';
import type { RuleConfigRecord, RuleEvaluationInput } from './rule.types.js';

const cfg = (
  key: string,
  points: [string, number][],
  params: Record<string, unknown> = {},
): RuleConfigRecord => ({
  key,
  name: key,
  enabled: true,
  points: points.map(([condition, p]) => ({ condition, points: p })),
  params,
});
const input = (
  over: Partial<RuleEvaluationInput> = {},
): RuleEvaluationInput => ({
  originalDomain: 'paypal.com',
  fuzzerDomain: 'apypal.com',
  dns: { a: ['1.2.3.4'], aaaa: [], mx: [], ns: ['ns1.x'], ttl: 600 },
  ...over,
});
const config = {
  get: (k: string) =>
    k === 'dns' ? { nameservers: [] } : { ruleNetworkTimeoutMs: 1_000 },
} as unknown as ConfigService<AppConfig, true>;

describe('BaseRule (via concrete rules)', () => {
  it('returns 0 points with condition "default" when the rule is disabled', async () => {
    const r = await new DnsResolvesRule().evaluate(
      { ...cfg('dns_resolves', [['resolved_ip', 10]]), enabled: false },
      input(),
    );
    expect(r).toEqual({
      key: 'dns_resolves',
      matched: false,
      condition: 'default',
      value: 'rule disabled',
      points: 0,
    });
  });

  it('falls back to the "default" tier when no tier matches the condition', async () => {
    const r = await new DnsResolvesRule().evaluate(
      cfg('dns_resolves', [['default', 0]]),
      input(),
    );
    expect(r).toMatchObject({
      matched: false,
      condition: 'default',
      value: '1.2.3.4',
      points: 0,
    });
  });
});

describe('local rules (Reporting semantics)', () => {
  it('levenshtein: distance 1–3 matches tier "4"', async () => {
    expect(levenshtein('paypal.com', 'apypal.com')).toBe(2);
    expect(levenshtein('ABC', 'abc')).toBe(0);
    const rule = new LevenshteinDistanceRule();
    const c = cfg('levenshtein_distance', [
      ['4', 10],
      ['default', 0],
    ]);
    expect(await rule.evaluate(c, input())).toMatchObject({
      points: 10,
      value: 2,
    });
    expect(
      await rule.evaluate(
        c,
        input({ fuzzerDomain: 'paypal-secure-login.com' }),
      ),
    ).toMatchObject({ points: 0 });
  });

  it('suspicious TLD matches the last label against params.tlds', async () => {
    const c = cfg(
      'suspicious_tld',
      [
        ['matched', 15],
        ['default', 0],
      ],
      { tlds: ['.tk', '.xyz'] },
    );
    expect(
      await new SuspiciousTldRule().evaluate(
        c,
        input({ fuzzerDomain: 'paypal.XYZ'.toLowerCase() }),
      ),
    ).toMatchObject({ points: 15 });
    expect(await new SuspiciousTldRule().evaluate(c, input())).toMatchObject({
      points: 0,
      value: '.com',
    });
  });

  it('domain age < 30 days scores; missing WHOIS does not', async () => {
    const c = cfg('domain_age', [
      ['30', 20],
      ['default', 0],
    ]);
    const recent = new Date(Date.now() - 5 * 86_400_000);
    expect(
      await new DomainAgeRule().evaluate(
        c,
        input({ whois: { createdDate: recent } }),
      ),
    ).toMatchObject({ points: 20, value: 5 });
    expect(await new DomainAgeRule().evaluate(c, input())).toMatchObject({
      points: 0,
      value: 'not found',
    });
  });

  it('MX present, DNS resolves and low TTL', async () => {
    expect(
      await new MxRecordsFoundRule().evaluate(
        cfg('mx', [['exist', 15]]),
        input({ dns: { a: [], aaaa: [], mx: ['mx1.x'], ns: [], ttl: null } }),
      ),
    ).toMatchObject({ points: 15 });
    expect(
      await new DnsResolvesRule().evaluate(
        cfg('d', [['resolved_ip', 10]]),
        input({ dns: { a: [], aaaa: ['::1'], mx: [], ns: [], ttl: null } }),
      ),
    ).toMatchObject({ points: 10, value: '::1' });
    const ttl = cfg('low_ttl', [
      ['300', 15],
      ['default', 0],
    ]);
    expect(
      await new LowTtlRule().evaluate(
        ttl,
        input({ dns: { a: [], aaaa: [], mx: [], ns: [], ttl: 60 } }),
      ),
    ).toMatchObject({ points: 15 });
    expect(await new LowTtlRule().evaluate(ttl, input())).toMatchObject({
      points: 0,
      value: 600,
    });
  });
});

describe('network rule helpers', () => {
  it('reads the DMARC policy from chunked TXT records', () => {
    expect(
      extractDmarcPolicy([
        ['v=spf1 -all'],
        ['v=DMARC1; p=rej', 'ect; rua=mailto:x@y'],
      ]),
    ).toBe('reject');
    expect(extractDmarcPolicy([['v=DMARC1; rua=mailto:x@y']])).toBeNull();
  });

  it('DMARC rule: lookup failure counts as "missing"', async () => {
    const rule = new DmarcMissingRule(config);
    vi.spyOn(rule, 'checkDmarc').mockResolvedValue('missing');
    expect(
      await rule.evaluate(
        cfg('dmarc', [
          ['missing', 15],
          ['reject', 0],
        ]),
        input(),
      ),
    ).toMatchObject({ points: 15 });
  });

  it('Spamhaus: real listing codes only; refusals are unknown, not listings', () => {
    expect(interpretSpamhaus(['127.0.0.2'])).toEqual({
      status: 'listed',
      code: '127.0.0.2',
    });
    expect(interpretSpamhaus(['127.255.255.254'])).toEqual({
      status: 'refused',
    });
    expect(interpretSpamhaus([])).toEqual({ status: 'clean' });
  });

  it('Spamhaus rule: refused → no result; listed → points', async () => {
    const rule = new SpamhausBlacklistRule(config);
    const c = cfg('spamhaus', [
      ['listed', 10],
      ['default', 0],
    ]);
    vi.spyOn(rule, 'lookup').mockResolvedValueOnce({ status: 'refused' });
    expect(await rule.evaluate(c, input())).toMatchObject({
      condition: null,
      points: 0,
    });
    vi.spyOn(rule, 'lookup').mockResolvedValueOnce({
      status: 'listed',
      code: '127.0.0.3',
    });
    expect(await rule.evaluate(c, input())).toMatchObject({
      points: 10,
      value: '127.0.0.3',
    });
  });

  it('reputation rule maps found / not found / unknown', async () => {
    const reputation = { check: vi.fn() } as unknown as ReputationService & {
      check: ReturnType<typeof vi.fn>;
    };
    const rule = new ReputationCheckRule(reputation);
    const c = cfg('reputation_check', [
      ['found', 40],
      ['default', 0],
    ]);
    reputation.check.mockResolvedValueOnce({
      status: 'found',
      indicatorType: 'IPV4',
      value: '1.2.3.4',
      severity: 'high',
    });
    expect(await rule.evaluate(c, input())).toMatchObject({
      points: 40,
      value: 'manage-feed IPV4 1.2.3.4',
    });
    expect(reputation.check).toHaveBeenCalledWith('apypal.com', '1.2.3.4');
    reputation.check.mockResolvedValueOnce({
      status: 'unknown',
      reason: 'circuit open',
    });
    expect(await rule.evaluate(c, input())).toMatchObject({
      points: 0,
      value: 'unknown: circuit open',
    });
  });
});

describe('SslIssuesRule against a real TLS server', () => {
  let port: number;
  let close: () => void;

  beforeAll(async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ssl-'));
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=localhost',
        '-keyout',
        join(dir, 'k.pem'),
        '-out',
        join(dir, 'c.pem'),
      ],
      { stdio: 'ignore' },
    );
    const server = createServer(
      {
        key: readFileSync(join(dir, 'k.pem')),
        cert: readFileSync(join(dir, 'c.pem')),
      },
      (_q, s) => s.end('ok'),
    );
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    port = (server.address() as { port: number }).port;
    close = () => server.close();
  });
  afterAll(() => close());

  it('classifies a self-signed certificate', async () => {
    const result = await new SslIssuesRule(config).check('localhost', [], port);
    expect(result).toMatchObject({
      hasHttps: true,
      isSelfSigned: true,
      isValid: false,
    });
  });

  it('reads the authorization error code whether Node gives a string or an Error', async () => {
    const { authorizationErrorCode } = await import('./rules/network.rules.js');
    expect(authorizationErrorCode('CERT_HAS_EXPIRED')).toBe('CERT_HAS_EXPIRED');
    expect(
      authorizationErrorCode(
        Object.assign(new Error('x'), { code: 'SELF_SIGNED_CERT_IN_CHAIN' }),
      ),
    ).toBe('SELF_SIGNED_CERT_IN_CHAIN');
    expect(authorizationErrorCode(undefined)).toBeUndefined();
  });

  it('reports no HTTPS when nothing listens', async () => {
    const rule = new SslIssuesRule(config);
    const r = await rule.evaluate(
      cfg('ssl', [
        ['missing', 10],
        ['default', 0],
      ]),
      input({ fuzzerDomain: '127.0.0.1' }),
    );
    // 127.0.0.1:443 is closed in test environments → missing
    expect(r).toMatchObject({ condition: 'missing', points: 10 });
  });
});
