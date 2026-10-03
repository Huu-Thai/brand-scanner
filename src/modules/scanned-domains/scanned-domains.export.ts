import { createHash } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../config/configuration.js';
import { DomainStatus } from '../../database/generated/prisma/enums.js';
import { PrismaService } from '../../database/prisma.service.js';
import type {
  ExportFormat,
  ScannedDomainFilters,
} from './dto/scanned-domain.dto.js';
import { buildScannedDomainWhere } from './scanned-domains.read.service.js';

const PAGE = 1_000;

type ExportRow = {
  id: string;
  domain: string;
  unicodeDomain: string;
  fuzzer: string;
  status: DomainStatus;
  threatLevel: string;
  riskScore: number;
  tags: string[];
  dnsA: string[];
  dnsMx: string[];
  dnsNs: string[];
  firstSeenAt: Date;
  lastSeenAt: Date;
  updatedAt: Date;
  originalDomain: { domain: string };
};

const CSV_COLUMNS = [
  'domain',
  'unicode_domain',
  'original_domain',
  'fuzzer',
  'status',
  'threat_level',
  'risk_score',
  'dns_a',
  'dns_mx',
  'dns_ns',
  'tags',
  'first_seen_at',
  'last_seen_at',
] as const;

/** RFC 4180 field quoting, plus a leading quote on formula-like values (CSV injection). */
export function csvField(value: unknown): string {
  let s = value === null || value === undefined ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Deterministic UUIDv5-style id so re-exporting the same domain updates rather than duplicates in a TIP. */
export function stixId(type: string, key: string): string {
  const h = createHash('sha1')
    .update(`fuzzer-scanner:${type}:${key}`)
    .digest('hex');
  return `${type}--${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 0x3) | 0x8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

const STIX_IDENTITY = {
  type: 'identity',
  spec_version: '2.1',
  id: stixId('identity', 'fuzzer-scanner'),
  created: '2026-10-01T00:00:00.000Z',
  modified: '2026-10-01T00:00:00.000Z',
  name: 'Fuzzer Scanner',
  identity_class: 'system',
};

export function toStixIndicator(r: ExportRow) {
  const confirmed =
    r.status === DomainStatus.CONFIRMED_THREAT ||
    r.status === DomainStatus.TAKEN_DOWN;
  return {
    type: 'indicator',
    spec_version: '2.1',
    id: stixId('indicator', r.domain),
    created_by_ref: STIX_IDENTITY.id,
    created: r.firstSeenAt.toISOString(),
    modified: r.updatedAt.toISOString(),
    name: `Look-alike of ${r.originalDomain.domain}: ${r.domain}`,
    description: `Registered ${r.fuzzer} permutation of ${r.originalDomain.domain}; status ${r.status}, risk ${r.riskScore} (${r.threatLevel}).`,
    indicator_types: confirmed
      ? ['malicious-activity']
      : ['anomalous-activity'],
    pattern: `[domain-name:value = '${r.domain.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}']`,
    pattern_type: 'stix',
    valid_from: r.firstSeenAt.toISOString(),
    confidence: confirmed ? 90 : Math.min(80, Math.max(10, r.riskScore)),
    labels: [
      'typosquatting',
      `fuzzer:${r.fuzzer}`,
      `status:${r.status.toLowerCase()}`,
      `threat:${r.threatLevel.toLowerCase()}`,
    ],
  };
}

/** Streams look-alikes matching the list filters as CSV, JSON or a STIX 2.1 bundle. */
@Injectable()
export class ScannedDomainsExportService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  contentType(format: ExportFormat): string {
    return format === 'csv'
      ? 'text/csv; charset=utf-8'
      : 'application/json; charset=utf-8';
  }

  async *stream(
    filters: ScannedDomainFilters,
    format: ExportFormat,
  ): AsyncGenerator<string> {
    const max = this.config.get('export', { infer: true }).maxRows;
    let first = true;
    if (format === 'csv') yield `${CSV_COLUMNS.join(',')}\r\n`;
    if (format === 'json') yield '[';
    if (format === 'stix')
      yield `{"type":"bundle","id":"bundle--${crypto.randomUUID()}","objects":[${JSON.stringify(STIX_IDENTITY)}`;

    for await (const row of this.rows(filters, max)) {
      if (format === 'csv') {
        yield `${[
          row.domain,
          row.unicodeDomain,
          row.originalDomain.domain,
          row.fuzzer,
          row.status,
          row.threatLevel,
          row.riskScore,
          (row.dnsA ?? []).join(' '),
          (row.dnsMx ?? []).join(' '),
          (row.dnsNs ?? []).join(' '),
          (row.tags ?? []).join(' '),
          row.firstSeenAt.toISOString(),
          row.lastSeenAt.toISOString(),
        ]
          .map(csvField)
          .join(',')}\r\n`;
      } else if (format === 'json') {
        yield `${first ? '' : ','}${JSON.stringify({ ...row, originalDomain: row.originalDomain.domain })}`;
      } else {
        yield `,${JSON.stringify(toStixIndicator(row))}`;
      }
      first = false;
    }
    if (format === 'json') yield ']';
    if (format === 'stix') yield ']}';
  }

  /** Keyset pagination by id — constant memory regardless of export size. */
  private async *rows(
    filters: ScannedDomainFilters,
    max: number,
  ): AsyncGenerator<ExportRow> {
    const where = buildScannedDomainWhere(filters);
    let cursor: string | undefined;
    let emitted = 0;
    while (emitted < max) {
      const page = await this.prisma.scannedDomain.findMany({
        where: cursor ? { AND: [where, { id: { gt: cursor } }] } : where,
        orderBy: { id: 'asc' },
        take: Math.min(PAGE, max - emitted),
        select: {
          id: true,
          domain: true,
          unicodeDomain: true,
          fuzzer: true,
          status: true,
          threatLevel: true,
          riskScore: true,
          tags: true,
          dnsA: true,
          dnsMx: true,
          dnsNs: true,
          firstSeenAt: true,
          lastSeenAt: true,
          updatedAt: true,
          originalDomain: { select: { domain: true } },
        },
      });
      for (const row of page) yield row as ExportRow;
      emitted += page.length;
      if (page.length === 0 || page.length < PAGE) return;
      cursor = page[page.length - 1].id;
    }
  }
}
