# syntax=docker/dockerfile:1.7
# Targets: api · worker · migrate — same build, different entrypoints.

FROM node:24-alpine AS deps
WORKDIR /app
# Schema + config first: `npm ci` runs `prisma generate` via postinstall.
COPY package.json package-lock.json .npmrc prisma.config.ts ./
COPY src/database/prisma ./src/database/prisma
RUN DATABASE_URL=postgresql://build:build@localhost:5432/build npm ci --no-audit --no-fund

FROM deps AS build
COPY . .
RUN npm run build

# Runtime dependencies only (no test/build tooling). The generated Prisma client is compiled
# into dist/, so no `prisma generate` runs here. Note: npm records the Prisma CLI as a
# production package because it satisfies an optional peer of @prisma/client, so it is still
# installed; its vulnerable transitive deps are pinned to patched versions via `overrides`.
FROM node:24-alpine AS prod-deps
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

FROM node:24-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup -S app && adduser -S app -G app
COPY --from=prod-deps --chown=app:app /app/node_modules ./node_modules
COPY --from=build --chown=app:app /app/package.json ./
COPY --from=build --chown=app:app /app/dist ./dist
USER app

FROM runtime AS api
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD wget -qO- http://127.0.0.1:3000/api/v1/health/live >/dev/null || exit 1
CMD ["node", "dist/main.js"]

FROM runtime AS worker
CMD ["node", "dist/worker.main.js"]

# Release job: applies reviewed migrations (never on app boot). Uses the full toolchain.
FROM node:24-alpine AS migrate
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json prisma.config.ts ./
COPY src/database/prisma ./src/database/prisma
CMD ["npx", "prisma", "migrate", "deploy"]
