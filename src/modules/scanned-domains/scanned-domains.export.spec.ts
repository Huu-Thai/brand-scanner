import { DomainStatus } from '../../database/generated/prisma/enums.js';
import {
  csvField,
  ScannedDomainsExportService,
  stixId,
  toStixIndicator,
} from './scanned-domains.export.js';

const row = (i: number, over: Record<string, unknown> = {}) => ({
  id: `id-${String(i).padStart(4, '0')}`,
  domain: `d${i}.com`,
  unicodeDomain: `d${i}.com`,
  fuzzer: 'homoglyph',
  status: DomainStatus.ACTIVE,
  threatLevel: 'MEDIUM_RISK',
  riskScore: 55,
  tags: ['a', 'b'],
  dnsA: ['1.1.1.1'],
  dnsMx: [],
  dnsNs: ['ns.x'],
  firstSeenAt: new Date('2026-01-01T00:00:00Z'),
  lastSeenAt: new Date('2026-01-02T00:00:00Z'),
  updatedAt: new Date('2026-01-03T00:00:00Z'),
  originalDomain: { domain: 'paypal.com' },
  ...over,
});

function service(total: number, maxRows = 100_000) {
  const all = Array.from({ length: total }, (_, i) => row(i));
  const findMany = vi.fn(
    async (args: {
      where: { AND?: [unknown, { id: { gt: string } }] };
      take: number;
    }) => {
      const after = args.where.AND?.[1].id.gt;
      return all.filter((r) => !after || r.id > after).slice(0, args.take);
    },
  );
  const svc = new ScannedDomainsExportService(
    { scannedDomain: { findMany } } as never,
    { get: () => ({ maxRows }) } as never,
  );
  return { svc, findMany };
}

const collect = async (gen: AsyncGenerator<string>) => {
  let out = '';
  for await (const chunk of gen) out += chunk;
  return out;
};

describe('export helpers', () => {
  it('quotes CSV fields per RFC 4180 and neutralises formulas', () => {
    expect(csvField('plain')).toBe('plain');
    expect(csvField('a,b')).toBe('"a,b"');
    expect(csvField('say "hi"')).toBe('"say ""hi"""');
    expect(csvField('=HYPERLINK("x")')).toBe(`"'=HYPERLINK(""x"")"`);
    expect(csvField('-1')).toBe("'-1");
    expect(csvField(null)).toBe('');
  });

  it('derives stable, well-formed STIX ids', () => {
    const id = stixId('indicator', 'a.com');
    expect(id).toBe(stixId('indicator', 'a.com'));
    expect(id).not.toBe(stixId('indicator', 'b.com'));
    expect(id).toMatch(
      /^indicator--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it('labels confirmed threats as malicious with high confidence', () => {
    const confirmed = toStixIndicator(
      row(1, { status: DomainStatus.CONFIRMED_THREAT }) as never,
    );
    expect(confirmed).toMatchObject({
      indicator_types: ['malicious-activity'],
      confidence: 90,
      pattern: "[domain-name:value = 'd1.com']",
    });
    expect(toStixIndicator(row(2) as never)).toMatchObject({
      indicator_types: ['anomalous-activity'],
      confidence: 55,
    });
  });
});

describe('ScannedDomainsExportService', () => {
  it('streams CSV across keyset pages', async () => {
    const { svc, findMany } = service(2_500);
    const csv = await collect(svc.stream({}, 'csv'));
    const lines = csv.trimEnd().split('\r\n');
    expect(lines[0]).toMatch(/^domain,unicode_domain,original_domain,/);
    expect(lines).toHaveLength(2_501);
    expect(lines[1]).toBe(
      'd0.com,d0.com,paypal.com,homoglyph,ACTIVE,MEDIUM_RISK,55,1.1.1.1,,ns.x,a b,2026-01-01T00:00:00.000Z,2026-01-02T00:00:00.000Z',
    );
    expect(findMany).toHaveBeenCalledTimes(3);
  });

  it('caps the export at EXPORT_MAX_ROWS', async () => {
    const { svc } = service(50, 10);
    expect(JSON.parse(await collect(svc.stream({}, 'json')))).toHaveLength(10);
  });

  it('produces valid JSON and STIX bundles (including when empty)', async () => {
    const json = JSON.parse(await collect(service(3).svc.stream({}, 'json')));
    expect(json[0]).toMatchObject({
      domain: 'd0.com',
      originalDomain: 'paypal.com',
    });
    expect(
      JSON.parse(await collect(service(0).svc.stream({}, 'json'))),
    ).toEqual([]);

    const bundle = JSON.parse(await collect(service(2).svc.stream({}, 'stix')));
    expect(bundle.type).toBe('bundle');
    expect(bundle.objects.map((o: { type: string }) => o.type)).toEqual([
      'identity',
      'indicator',
      'indicator',
    ]);
  });

  it('declares the right content type', () => {
    const { svc } = service(0);
    expect(svc.contentType('csv')).toMatch(/text\/csv/);
    expect(svc.contentType('stix')).toMatch(/application\/json/);
  });
});
