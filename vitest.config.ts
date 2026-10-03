import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    root: './',
    include: ['src/**/*.spec.ts'],
    restoreMocks: true,
    setupFiles: ['src/testing/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text-summary', 'text', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/*.spec.ts',
        'src/database/generated/**',
        'src/database/prisma/seed.ts',
        'src/main.ts',
        'src/worker.main.ts',
        'src/bootstrap.ts', // exercised by the e2e suite
        'src/**/*.module.ts', // wiring only; covered by e2e
        'src/**/dto/**',
        'src/testing/**',
      ],
      // PLAN.md §11 gate (80 / 75), ratcheted in Phase 4 to just below the measured level
      // (≈ 92% lines, 80% branches) so coverage can only go up. CI fails below these.
      thresholds: { lines: 85, statements: 85, functions: 80, branches: 77 },
    },
  },
});
