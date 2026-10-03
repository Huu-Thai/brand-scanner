import 'dotenv/config';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../generated/prisma/client.js';

/**
 * Development seed. Reference data (rule_configs, scoring_thresholds) ships in
 * migration 0004 so every environment has it; this only adds sample data.
 * Idempotent: upserts on natural unique keys, parents before children.
 */
async function main(): Promise<void> {
  const prisma = new PrismaClient({
    adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL }),
  });
  try {
    const original = await prisma.originalDomain.upsert({
      where: { domain: 'example.com' },
      update: {},
      create: {
        domain: 'example.com',
        unicodeDomain: 'example.com',
        label: 'Example brand (seed)',
        scanSchedule: '0 2 * * *',
        scanOptions: { includeWhois: true, includeScreenshots: true },
      },
    });
    const rules = await prisma.ruleConfig.count();
    console.log(
      `Seeded original domain ${original.domain} (${original.id}); ${rules} scoring rules present`,
    );
  } finally {
    await prisma.$disconnect();
  }
}

await main();
