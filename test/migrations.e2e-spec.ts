/**
 * Migration verification (PLAN.md §3.3): applies the committed migrations to an
 * empty PostgreSQL 16 and asserts primary keys, foreign keys (with referential
 * actions), FK indexes and behaviour. Fails CI if a migration and schema.prisma drift.
 */
import {
  PostgreSqlContainer,
  type StartedPostgreSqlContainer,
} from '@testcontainers/postgresql';
import pg from 'pg';
import {
  FOREIGN_KEYS,
  UNIQUE_CONSTRAINTS,
} from '../src/database/constraints.js';
import { prisma } from './support/migrate.js';

const TABLES = [
  'alert_channels',
  'alert_deliveries',
  'alert_subscriptions',
  'analytics',
  'brand_references',
  'original_domains',
  'outbox_events',
  'reviews',
  'rule_configs',
  'scanned_domains',
  'scans',
  'scoring_thresholds',
  'screenshots',
  'whois_informations',
];

// constraint → [table, column, referenced table, on delete, on update]  (c = CASCADE, n = SET NULL)
const EXPECTED_FKS: Record<string, [string, string, string, string, string]> = {
  fk_brand_references_original_domain_id: [
    'brand_references',
    'original_domain_id',
    'original_domains',
    'c',
    'c',
  ],
  fk_alert_subscriptions_channel_id: [
    'alert_subscriptions',
    'channel_id',
    'alert_channels',
    'c',
    'c',
  ],
  fk_alert_subscriptions_original_domain_id: [
    'alert_subscriptions',
    'original_domain_id',
    'original_domains',
    'c',
    'c',
  ],
  fk_alert_deliveries_subscription_id: [
    'alert_deliveries',
    'subscription_id',
    'alert_subscriptions',
    'c',
    'c',
  ],
  fk_alert_deliveries_channel_id: [
    'alert_deliveries',
    'channel_id',
    'alert_channels',
    'c',
    'c',
  ],
  fk_alert_deliveries_scanned_domain_id: [
    'alert_deliveries',
    'scanned_domain_id',
    'scanned_domains',
    'n',
    'c',
  ],
  fk_scans_original_domain_id: [
    'scans',
    'original_domain_id',
    'original_domains',
    'c',
    'c',
  ],
  fk_scanned_domains_original_domain_id: [
    'scanned_domains',
    'original_domain_id',
    'original_domains',
    'c',
    'c',
  ],
  fk_scanned_domains_last_scan_id: [
    'scanned_domains',
    'last_scan_id',
    'scans',
    'n',
    'c',
  ],
  fk_whois_informations_scanned_domain_id: [
    'whois_informations',
    'scanned_domain_id',
    'scanned_domains',
    'c',
    'c',
  ],
  fk_screenshots_scanned_domain_id: [
    'screenshots',
    'scanned_domain_id',
    'scanned_domains',
    'c',
    'c',
  ],
  fk_screenshots_scan_id: ['screenshots', 'scan_id', 'scans', 'n', 'c'],
  fk_reviews_scanned_domain_id: [
    'reviews',
    'scanned_domain_id',
    'scanned_domains',
    'c',
    'c',
  ],
  fk_analytics_scanned_domain_id: [
    'analytics',
    'scanned_domain_id',
    'scanned_domains',
    'c',
    'c',
  ],
  fk_analytics_scan_id: ['analytics', 'scan_id', 'scans', 'n', 'c'],
};

describe('database migrations', () => {
  let container: StartedPostgreSqlContainer;
  let db: pg.Client;
  let url: string;

  beforeAll(async () => {
    container = await new PostgreSqlContainer('postgres:16-alpine').start();
    url = container.getConnectionUri();
    prisma(['migrate', 'deploy'], url);
    db = new pg.Client({ connectionString: url });
    await db.connect();
  });

  afterAll(async () => {
    await db?.end();
    await container?.stop();
  });

  it('has no drift between migrations and schema.prisma', () => {
    // --exit-code: 0 = no difference, 2 = drift (execFileSync throws on non-zero).
    expect(() =>
      prisma(
        [
          'migrate',
          'diff',
          '--from-config-datasource',
          '--to-schema',
          'src/database/prisma/schema.prisma',
          '--exit-code',
        ],
        url,
      ),
    ).not.toThrow();
  });

  it('gives every table a UUID primary key named pk_<table>, defaulting to gen_random_uuid()', async () => {
    const { rows } = await db.query<{
      table_name: string;
      constraint_name: string;
      data_type: string;
      column_default: string;
    }>(`
      SELECT tc.table_name, tc.constraint_name, c.data_type, c.column_default
      FROM information_schema.table_constraints tc
      JOIN information_schema.key_column_usage k
        ON k.constraint_name = tc.constraint_name AND k.table_schema = tc.table_schema
      JOIN information_schema.columns c
        ON c.table_name = tc.table_name AND c.column_name = k.column_name AND c.table_schema = tc.table_schema
      WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = 'public' AND tc.table_name <> '_prisma_migrations'
      ORDER BY tc.table_name`);
    expect(rows.map((r) => r.table_name)).toEqual(TABLES);
    for (const row of rows) {
      expect(row.constraint_name).toBe(`pk_${row.table_name}`);
      expect(row.data_type).toBe('uuid');
      expect(row.column_default).toBe('gen_random_uuid()');
    }
  });

  it('has exactly the planned foreign keys with their referential actions', async () => {
    const { rows } = await db.query<{
      conname: string;
      tbl: string;
      col: string;
      ref: string;
      confdeltype: string;
      confupdtype: string;
      convalidated: boolean;
    }>(`
      SELECT c.conname, t.relname AS tbl, a.attname AS col, r.relname AS ref,
             c.confdeltype, c.confupdtype, c.convalidated
      FROM pg_constraint c
      JOIN pg_class t ON t.oid = c.conrelid
      JOIN pg_class r ON r.oid = c.confrelid
      JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
      WHERE c.contype = 'f'
      ORDER BY c.conname`);
    const actual = Object.fromEntries(
      rows.map((r) => [
        r.conname,
        [r.tbl, r.col, r.ref, r.confdeltype, r.confupdtype],
      ]),
    );
    expect(actual).toEqual(EXPECTED_FKS);
    expect(rows.every((r) => r.convalidated)).toBe(true);
    // Every FK has a client-safe error message in the API's constraint map.
    expect(Object.keys(FOREIGN_KEYS).sort()).toEqual(
      Object.keys(EXPECTED_FKS).sort(),
    );
  });

  it('indexes every foreign-key column (as the leading index column)', async () => {
    const { rows } = await db.query<{ conname: string; indexed: boolean }>(`
      SELECT c.conname,
             EXISTS (
               SELECT 1 FROM pg_index i
               WHERE i.indrelid = c.conrelid AND i.indkey[0] = c.conkey[1]
             ) AS indexed
      FROM pg_constraint c WHERE c.contype = 'f'`);
    expect(rows.filter((r) => !r.indexed).map((r) => r.conname)).toEqual([]);
  });

  it('names every unique constraint as documented', async () => {
    const { rows } = await db.query<{ indexname: string }>(`
      SELECT indexname FROM pg_indexes
      WHERE schemaname = 'public' AND indexdef LIKE 'CREATE UNIQUE INDEX%' AND indexname NOT LIKE 'pk_%'
        AND tablename <> '_prisma_migrations'`);
    expect(rows.map((r) => r.indexname).sort()).toEqual(
      Object.keys(UNIQUE_CONSTRAINTS).sort(),
    );
  });

  it('ships the scoring reference data', async () => {
    const rules = await db.query<{ key: string }>(
      'SELECT key FROM rule_configs ORDER BY key',
    );
    expect(rules.rows).toHaveLength(12);
    const thresholds = await db.query(
      'SELECT threshold_medium_risk, threshold_low_risk FROM scoring_thresholds',
    );
    expect(thresholds.rows).toEqual([
      { threshold_medium_risk: 80, threshold_low_risk: 40 },
    ]);
    const rep = await db.query<{ params: unknown }>(
      `SELECT params FROM rule_configs WHERE key = 'reputation_check'`,
    );
    expect(rep.rows[0].params).toEqual({ provider: 'threat-feed' });
  });

  describe('referential behaviour', () => {
    async function seedGraph() {
      const od = await db.query<{ id: string }>(
        `INSERT INTO original_domains (domain, unicode_domain, updated_at) VALUES ($1, $1, now()) RETURNING id`,
        [`brand-${Math.random().toString(36).slice(2)}.com`],
      );
      const originalId = od.rows[0].id;
      const scan = await db.query<{ id: string }>(
        `INSERT INTO scans (original_domain_id, updated_at) VALUES ($1, now()) RETURNING id`,
        [originalId],
      );
      const scanId = scan.rows[0].id;
      const sd = await db.query<{ id: string }>(
        `INSERT INTO scanned_domains (original_domain_id, last_scan_id, domain, unicode_domain, fuzzer, updated_at)
         VALUES ($1, $2, 'brnad.com', 'brnad.com', 'transposition', now()) RETURNING id`,
        [originalId, scanId],
      );
      const scannedId = sd.rows[0].id;
      await db.query(
        `INSERT INTO analytics (scanned_domain_id, scan_id, total_score, threat_level, rule_results)
         VALUES ($1, $2, 55, 'MEDIUM_RISK', '[]')`,
        [scannedId, scanId],
      );
      await db.query(
        `INSERT INTO screenshots (scanned_domain_id, scan_id, requested_url, updated_at) VALUES ($1, $2, 'https://brnad.com', now())`,
        [scannedId, scanId],
      );
      await db.query(
        `INSERT INTO whois_informations (scanned_domain_id, source) VALUES ($1, 'RDAP')`,
        [scannedId],
      );
      await db.query(
        `INSERT INTO reviews (scanned_domain_id, verdict, reviewer, previous_status, new_status)
         VALUES ($1, 'SUSPICIOUS', 'ci', 'NEW', 'UNDER_REVIEW')`,
        [scannedId],
      );
      return { originalId, scanId, scannedId };
    }

    it('rejects a child row pointing at a missing parent (23503)', async () => {
      await expect(
        db.query(
          `INSERT INTO scans (original_domain_id, updated_at) VALUES (gen_random_uuid(), now())`,
        ),
      ).rejects.toMatchObject({
        code: '23503',
        constraint: 'fk_scans_original_domain_id',
      });
      await expect(
        db.query(
          `INSERT INTO reviews (scanned_domain_id, verdict, reviewer, previous_status, new_status)
           VALUES (gen_random_uuid(), 'BENIGN', 'ci', 'NEW', 'ACTIVE')`,
        ),
      ).rejects.toMatchObject({
        code: '23503',
        constraint: 'fk_reviews_scanned_domain_id',
      });
    });

    it('deleting a scan keeps its domain and history but nulls the scan references', async () => {
      const { scanId, scannedId } = await seedGraph();
      await db.query('DELETE FROM scans WHERE id = $1', [scanId]);
      const sd = await db.query(
        'SELECT last_scan_id FROM scanned_domains WHERE id = $1',
        [scannedId],
      );
      expect(sd.rows).toEqual([{ last_scan_id: null }]);
      const a = await db.query(
        'SELECT scan_id FROM analytics WHERE scanned_domain_id = $1',
        [scannedId],
      );
      expect(a.rows).toEqual([{ scan_id: null }]);
      const s = await db.query(
        'SELECT scan_id FROM screenshots WHERE scanned_domain_id = $1',
        [scannedId],
      );
      expect(s.rows).toEqual([{ scan_id: null }]);
    });

    it('deleting an original domain cascades through every child table', async () => {
      const { originalId, scannedId } = await seedGraph();
      await db.query('DELETE FROM original_domains WHERE id = $1', [
        originalId,
      ]);
      for (const [table, column, id] of [
        ['scans', 'original_domain_id', originalId],
        ['scanned_domains', 'id', scannedId],
        ['analytics', 'scanned_domain_id', scannedId],
        ['screenshots', 'scanned_domain_id', scannedId],
        ['whois_informations', 'scanned_domain_id', scannedId],
        ['reviews', 'scanned_domain_id', scannedId],
      ]) {
        const { rowCount } = await db.query(
          `SELECT 1 FROM ${table} WHERE ${column} = $1`,
          [id],
        );
        expect({ table, rowCount }).toEqual({ table, rowCount: 0 });
      }
    });

    it('allows only one in-flight scan per original domain (partial unique index)', async () => {
      const { originalId } = await seedGraph(); // seedGraph's scan is QUEUED
      await expect(
        db.query(
          `INSERT INTO scans (original_domain_id, updated_at) VALUES ($1, now())`,
          [originalId],
        ),
      ).rejects.toMatchObject({
        code: '23505',
        constraint: 'uq_scans_active_original_domain',
      });
      // Finished scans are unconstrained: complete the active one, then two more may coexist.
      await db.query(
        `UPDATE scans SET status = 'COMPLETED' WHERE original_domain_id = $1`,
        [originalId],
      );
      await db.query(
        `INSERT INTO scans (original_domain_id, status, updated_at) VALUES ($1, 'FAILED', now())`,
        [originalId],
      );
      await db.query(
        `INSERT INTO scans (original_domain_id, updated_at) VALUES ($1, now())`,
        [originalId],
      );
    });

    it('enforces one tracked domain per original domain', async () => {
      const { originalId } = await seedGraph();
      await expect(
        db.query(
          `INSERT INTO scanned_domains (original_domain_id, domain, unicode_domain, fuzzer, updated_at)
           VALUES ($1, 'brnad.com', 'brnad.com', 'omission', now())`,
          [originalId],
        ),
      ).rejects.toMatchObject({
        code: '23505',
        constraint: 'uq_scanned_domains_original_domain_id_domain',
      });
    });
  });
});
