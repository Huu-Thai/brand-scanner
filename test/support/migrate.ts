import { execFileSync } from 'node:child_process';

/** Runs a Prisma CLI command against the given database (never the developer's .env database). */
export function prisma(args: string[], databaseUrl: string): string {
  return execFileSync('npx', ['prisma', ...args], {
    env: { ...process.env, DATABASE_URL: databaseUrl },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}
