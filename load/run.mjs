// Load test at the PLAN §16 sizing target: 10 brands × ~50k permutations scanned at once.
// SLOs checked: every full scan ≤ 2 h; WHOIS + score for every discovered look-alike ≤ 6 h;
// API p95 ≤ 500 ms for the list/summary endpoints while the pipeline is saturated.
//   node load/run.mjs --api http://127.0.0.1:3200/api/v1 --key <admin key> [--brands 10]
import { mkdirSync, writeFileSync } from 'node:fs';

const arg = (name, def) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : def;
};
const API = arg('api', 'http://127.0.0.1:3200/api/v1');
const KEY = arg('key', process.env.LOAD_API_KEY);
const BRANDS = Number(arg('brands', 10));
const POLL_MS = Number(arg('poll', 15_000));
// Worker metrics (one URL per worker process, comma separated): enrichment is done when the WHOIS
// and analytics queues are empty and WHOIS has handled every registered look-alike.
const METRICS = arg('metrics', 'http://127.0.0.1:9465/metrics').split(',');
const SLO = { scanMs: 2 * 3_600_000, enrichMs: 6 * 3_600_000, p95Ms: 500 };
if (!KEY) throw new Error('--key (admin API key) is required');

const NAMES = [
  'contoso-secure-banking', 'northwind-online-store', 'fabrikam-cloud-payments', 'adventureworks-cycles',
  'tailspin-airlines-mail', 'wingtiptoys-checkout', 'woodgrove-bank-online', 'litware-health-portal',
  'proseware-identity-hub', 'alpineskihouse-rentals', 'margies-travel-booking', 'bellows-college-alumni',
];

const call = async (method, path, body) => {
  const t = performance.now();
  const res = await fetch(API + path, {
    method,
    headers: { 'x-api-key': KEY, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body && JSON.stringify(body),
  });
  const ms = performance.now() - t;
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path} → ${res.status} ${text.slice(0, 200)}`);
  return { body: text ? JSON.parse(text) : null, ms };
};
const pct = (xs, p) => {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  return Math.round(s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)]);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

// API latency probe: runs for the whole test, a few concurrent readers like analysts in the console.
const latency = { list: [], summary: [], scans: [], errors: 0 };
let probing = true;
async function probe(originalDomainId) {
  while (probing) {
    try {
      latency.list.push((await call('GET', `/scanned-domains?sort=riskScore&order=desc&limit=50${originalDomainId ? `&originalDomainId=${originalDomainId}` : ''}`)).ms);
      latency.summary.push((await call('GET', `/analytics/summary${originalDomainId ? `?originalDomainId=${originalDomainId}` : ''}`)).ms);
      latency.scans.push((await call('GET', '/scans?limit=20')).ms);
    } catch {
      latency.errors++;
    }
    await sleep(1_000);
  }
}

const started = Date.now();
log(`load test: ${BRANDS} brands against ${API}`);
const brands = [];
for (const n of NAMES.slice(0, BRANDS)) {
  const domain = `${n}.com`;
  const existing = (await call('GET', `/original-domains?search=${encodeURIComponent(n)}`)).body.data.find((b) => b.domain === domain);
  brands.push(existing ?? (await call('POST', '/original-domains', { domain, label: 'load test' })).body);
}
const t0 = Date.now();
const scans = [];
for (const b of brands)
  scans.push((await call('POST', '/scans', { originalDomainId: b.id, options: { includeScreenshots: false } })).body);
log(`triggered ${scans.length} scans`);
const probes = [probe(), probe(brands[0].id), probe(brands[1]?.id)];

// Phase 1: discovery (DNS) — every scan COMPLETED.
const finished = new Map();
for (;;) {
  await sleep(POLL_MS);
  const rows = await Promise.all(scans.map((s) => call('GET', `/scans/${s.id}`).then((r) => r.body)));
  for (const r of rows) if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(r.status) && !finished.has(r.id)) finished.set(r.id, r);
  const perms = rows.reduce((a, r) => a + r.permutationsTotal, 0);
  const resolved = rows.reduce((a, r) => a + r.resolvedCount, 0);
  log(`discovery: ${finished.size}/${rows.length} scans done, ${resolved}/${perms} resolved, ${rows.reduce((a, r) => a + r.registeredCount, 0)} registered`);
  if (finished.size === rows.length) break;
}
const discoveryMs = Date.now() - t0;

// Phase 2: enrichment — WHOIS for every discovered look-alike, then its (re)score. Scoring also
// runs at discovery, so "nothing UNSCORED" is NOT the signal; the queues draining is.
const registeredTotal = [...finished.values()].reduce((a, s) => a + s.registeredCount, 0);
const metric = (text, re) => [...text.matchAll(re)].reduce((a, m) => a + Number(m[1]), 0);
async function workerState() {
  const texts = await Promise.all(METRICS.map((u) => fetch(u).then((r) => r.text()).catch(() => '')));
  const all = texts.join('\n');
  return {
    pending: metric(all, /^fuzzer_queue_jobs\{queue="(?:whois|analytics)",state="(?:waiting|active|delayed|prioritized)"\} (\d+)/gm),
    whoisDone: metric(all, /^fuzzer_whois_lookups_total\{result="(?:created|failed)"\} (\d+)/gm),
  };
}
let enrichMs = null;
let lastLog = 0;
let drainedChecks = 0;
for (;;) {
  const { pending, whoisDone } = await workerState();
  if (Date.now() - lastLog > 300_000) {
    log(`enrichment: WHOIS ${whoisDone}/${registeredTotal}, ${pending} WHOIS/analytics jobs pending`);
    lastLog = Date.now();
  }
  // Two consecutive empty polls: no follow-up jobs (re-scores) still being enqueued.
  drainedChecks = pending === 0 && whoisDone >= registeredTotal ? drainedChecks + 1 : 0;
  if (drainedChecks >= 2) {
    enrichMs = Date.now() - t0 - POLL_MS;
    break;
  }
  if (Date.now() - t0 > SLO.enrichMs + 1_800_000) break; // give up 30 min past the SLO
  await sleep(POLL_MS);
}
probing = false;
await Promise.all(probes);

const scanRows = [...finished.values()];
const durations = scanRows.map((s) => Date.parse(s.finishedAt) - Date.parse(s.createdAt));
const report = {
  startedAt: new Date(started).toISOString(),
  api: API,
  brands: brands.map((b) => b.domain),
  scans: scanRows.map((s) => ({
    brand: brands.find((b) => b.id === s.originalDomainId)?.domain,
    status: s.status,
    permutations: s.permutationsTotal,
    registered: s.registeredCount,
    failedLookups: s.failedCount,
    durationS: Math.round((Date.parse(s.finishedAt) - Date.parse(s.createdAt)) / 1000),
  })),
  whoisProcessed: (await workerState()).whoisDone,
  totals: {
    permutations: scanRows.reduce((a, s) => a + s.permutationsTotal, 0),
    registered: scanRows.reduce((a, s) => a + s.registeredCount, 0),
  },
  discoveryS: Math.round(discoveryMs / 1000),
  slowestScanS: Math.round(Math.max(...durations) / 1000),
  enrichmentS: enrichMs === null ? null : Math.round(enrichMs / 1000),
  apiLatencyMs: Object.fromEntries(
    ['list', 'summary', 'scans'].map((k) => [k, { n: latency[k].length, p50: pct(latency[k], 50), p95: pct(latency[k], 95), p99: pct(latency[k], 99) }]),
  ),
  apiErrors: latency.errors,
};
report.slo = {
  scanUnder2h: scanRows.every((s) => s.status === 'COMPLETED') && Math.max(...durations) <= SLO.scanMs,
  enrichmentUnder6h: enrichMs !== null && enrichMs <= SLO.enrichMs,
  apiP95Under500ms: ['list', 'summary', 'scans'].every((k) => (report.apiLatencyMs[k].p95 ?? Infinity) <= SLO.p95Ms),
};
report.pass = Object.values(report.slo).every(Boolean);
mkdirSync(new URL('./results/', import.meta.url), { recursive: true });
const file = new URL(`./results/load-${report.startedAt.replace(/[:.]/g, '-')}.json`, import.meta.url);
writeFileSync(file, JSON.stringify(report, null, 2));
log(JSON.stringify({ totals: report.totals, discoveryS: report.discoveryS, slowestScanS: report.slowestScanS, enrichmentS: report.enrichmentS, api: report.apiLatencyMs, slo: report.slo }, null, 2));
log(`report: ${file.pathname}`);
process.exit(report.pass ? 0 : 1);
