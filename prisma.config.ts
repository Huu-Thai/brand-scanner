import 'dotenv/config';
import { defineConfig } from 'prisma/config';

export default defineConfig({
  schema: 'src/database/prisma/schema.prisma',
  migrations: {
    path: 'src/database/prisma/migrations',
    // Seeds run from compiled output so they share the app's ESM build.
    seed: 'node dist/database/prisma/seed.js',
  },
  datasource: {
    url: process.env['DATABASE_URL'],
  },
});
