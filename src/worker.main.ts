import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { WorkerModule } from './worker.module.js';

// WORKER_QUEUES decides which modules are built, so it is read before ConfigModule loads .env.
try {
  process.loadEnvFile();
} catch {
  // no .env file — environment comes from the container / process manager
}
// Outbox rows are relayed by a process of the same role (it has the same listeners).
process.env.PROCESS_ROLE = 'worker';
const queues = (process.env.WORKER_QUEUES ?? '')
  .split(',')
  .map((q) => q.trim())
  .filter(Boolean);

async function bootstrap(): Promise<void> {
  const app = await NestFactory.createApplicationContext(
    WorkerModule.forQueues(queues),
    { bufferLogs: true },
  );
  app.useLogger(app.get(WINSTON_MODULE_NEST_PROVIDER));
  app.enableShutdownHooks();
  new Logger('Worker').log(
    `Worker started (${queues.length ? queues.join(', ') : 'all queues'})`,
  );
}

await bootstrap();
