#!/usr/bin/env node
// Operator tool for the BullMQ queues (docs/RUNBOOK.md). Reads the same env / .env as the app.
//   node scripts/queues.mjs stats
//   node scripts/queues.mjs failed <queue> [limit]        # newest failed jobs with their errors
//   node scripts/queues.mjs retry-failed <queue>          # move every failed job back to waiting
//   node scripts/queues.mjs clean-failed <queue> <hours>  # drop failed jobs older than <hours>
import { Queue } from 'bullmq';

try {
  process.loadEnvFile();
} catch {
  // environment comes from the shell / container
}

const QUEUES = [
  'scan-orchestrator', 'dns-resolve', 'scan-finalize', 'whois', 'screenshot', 'analytics',
  'scheduler', 'threat-feed-push', 'retention', 'domain-rescan',
];
const env = process.env;
const connection = {
  host: env.REDIS_HOST ?? 'localhost',
  port: Number(env.REDIS_PORT ?? 6379),
  username: env.REDIS_USERNAME || undefined,
  password: env.REDIS_PASSWORD,
  db: Number(env.REDIS_QUEUE_DB ?? 0),
  ...(env.REDIS_TLS === 'true' ? { tls: {} } : {}),
};
const prefix = env.BULLMQ_PREFIX || undefined;
const [cmd, name, extra] = process.argv.slice(2);
const open = (q) => new Queue(q, { connection, ...(prefix ? { prefix } : {}) });

function need(queue) {
  if (!QUEUES.includes(queue)) {
    console.error(`unknown queue "${queue}" (known: ${QUEUES.join(', ')})`);
    process.exit(2);
  }
}

if (cmd === 'stats') {
  const rows = [];
  for (const q of QUEUES) {
    const queue = open(q);
    const c = await queue.getJobCounts('waiting', 'active', 'delayed', 'failed', 'completed', 'prioritized');
    const [oldest] = await queue.getJobs(['waiting', 'prioritized'], 0, 0, true);
    rows.push({ queue: q, ...c, oldestWaitingS: oldest ? Math.round((Date.now() - oldest.timestamp) / 1000) : 0 });
    await queue.close();
  }
  console.table(rows);
} else if (cmd === 'failed') {
  need(name);
  const queue = open(name);
  for (const job of await queue.getFailed(0, Number(extra ?? 20) - 1))
    console.log(`${new Date(job.finishedOn ?? job.timestamp).toISOString()}  ${job.id}  attempts=${job.attemptsMade}  ${job.failedReason}`);
  await queue.close();
} else if (cmd === 'retry-failed') {
  need(name);
  const queue = open(name);
  const before = await queue.getFailedCount();
  await queue.retryJobs({ state: 'failed', count: 1000 });
  console.log(`retried ${before} failed job(s) in ${name}`);
  await queue.close();
} else if (cmd === 'clean-failed') {
  need(name);
  const hours = Number(extra);
  if (!Number.isFinite(hours) || hours < 0) {
    console.error('usage: clean-failed <queue> <hours>');
    process.exit(2);
  }
  const queue = open(name);
  const removed = await queue.clean(hours * 3_600_000, 10_000, 'failed');
  console.log(`removed ${removed.length} failed job(s) older than ${hours}h from ${name}`);
  await queue.close();
} else {
  console.log('usage: node scripts/queues.mjs stats | failed <queue> [limit] | retry-failed <queue> | clean-failed <queue> <hours>');
  process.exit(cmd ? 2 : 0);
}
