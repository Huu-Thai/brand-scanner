import { createServer, type Server } from 'node:http';
import {
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/configuration.js';
import { authorized } from './metrics.controller.js';
import { MetricsCollector } from './metrics.collector.js';

/** The worker has no HTTP API; it exposes GET /metrics on METRICS_PORT for Prometheus. */
@Injectable()
export class WorkerMetricsServer
  implements OnApplicationBootstrap, OnApplicationShutdown
{
  private readonly logger = new Logger(WorkerMetricsServer.name);
  private server?: Server;

  constructor(
    private readonly collector: MetricsCollector,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  onApplicationBootstrap(): Promise<void> | void {
    const { port, token } = this.config.get('metrics', { infer: true });
    if (this.config.get('processRole', { infer: true }) !== 'worker' || !port)
      return;
    this.server = createServer((req, res) => {
      if (req.method !== 'GET' || req.url?.split('?')[0] !== '/metrics') {
        res.writeHead(404).end();
        return;
      }
      if (!authorized(token, req.headers.authorization)) {
        res.writeHead(401).end();
        return;
      }
      this.collector
        .scrape()
        .then(({ contentType, body }) =>
          res.writeHead(200, { 'content-type': contentType }).end(body),
        )
        .catch(() => res.writeHead(500).end());
    });
    const server = this.server;
    return new Promise((resolve) => {
      // Metrics are optional for the worker: a busy port must never stop job processing.
      server.once('error', (e: NodeJS.ErrnoException) => {
        this.logger.error(
          e.code === 'EADDRINUSE'
            ? `Metrics port ${port} is already in use — worker runs without /metrics. Give each worker on this host its own METRICS_PORT (or 0 to disable).`
            : `Worker metrics server failed: ${e.message}`,
        );
        this.server = undefined;
        resolve();
      });
      server.listen(port, () => {
        this.logger.log(`Worker metrics on :${port}/metrics`);
        resolve();
      });
    });
  }

  async onApplicationShutdown(): Promise<void> {
    await new Promise((r) =>
      this.server ? this.server.close(r) : r(undefined),
    );
  }
}
