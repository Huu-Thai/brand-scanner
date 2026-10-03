# Load test

Exercises the full pipeline at the PLAN §16 sizing target: **10 brands × ~42k permutations (≈ 420k
DNS lookups) scanned at once**, then WHOIS and scoring for every discovered look-alike. Pass/fail is
judged against these SLOs:

| SLO | Target |
|---|---|
| Every full scan finishes (discovery) | ≤ 2 h |
| WHOIS + score for every discovered look-alike | ≤ 6 h after the scans were triggered |
| API p95 for list / summary / scans while the pipeline is saturated | ≤ 500 ms |

The test is **hermetic**: nothing is sent to public DNS, registries or websites.

| Edge | Replaced by | Model |
|---|---|---|
| DNS (resolver + DMARC/Spamhaus lookups) | `dns-stub.mjs` (UDP) | 1.5% of names registered (`REGISTERED_PER_MILLE`); 25 ± 15 ms per answer |
| RDAP | `rdap-stub.mjs` (HTTP) | `.com`/`.net` on one registry host, other TLDs spread over 20 hosts, 40–120 ms per answer. The client's real per-host limit (8 / 11 s) applies |
| TLS (SSL rule) | registered names resolve to 127.0.0.1, so the connection is refused at once | — |
| Screenshots | turned off for the test scans (`includeScreenshots: false`) | Browser capacity scales with Selenium Grid nodes; see RUNBOOK §5 |
| threat-feed | `THREAT_FEED_ENABLED=false` | Reputation lookups are cached in Redis and are not on the critical path |

## Running it

Use a separate database and separate Redis DB indexes so the run never touches real data:

```bash
createdb fuzzer_load                                    # or CREATE DATABASE in your Postgres
cat > load.env <<'EOF'
DATABASE_URL=postgresql://…/fuzzer_load?schema=public
REDIS_QUEUE_DB=5
REDIS_CACHE_DB=6
DNS_NAMESERVERS=127.0.0.1:5354
RDAP_BOOTSTRAP_URL=http://127.0.0.1:5380/bootstrap
THREAT_FEED_ENABLED=false
THROTTLE_LIMIT=100000
THROTTLE_EXPENSIVE_LIMIT=1000
METRICS_PORT=9465
EOF
node load/dns-stub.mjs & node load/rdap-stub.mjs &
set -a; . ./load.env; set +a
npx prisma migrate deploy && npm run build
PORT=3200 node dist/main.js & node dist/worker.main.js &
LOAD_API_KEY=<admin key> node load/run.mjs --api http://127.0.0.1:3200/api/v1 --metrics http://127.0.0.1:9465/metrics
```

The runner drives the public API only, as an operator would. It records per-scan durations, waits for
the WHOIS and analytics queues to drain (from the worker's `/metrics`), probes API latency the whole
time, and writes `load/results/load-<timestamp>.json`. The exit code is 0 only when every SLO holds.
Add `--metrics` URLs, comma separated, when you run several worker processes.

Run **one** worker for WHOIS per egress IP. The RDAP limit is per process, and real registries enforce
it per IP (RUNBOOK §3, FuzzerWhoisQueueLag).
