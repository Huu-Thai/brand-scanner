import { tmpdir } from 'node:os';
import { join } from 'node:path';
import winston from 'winston';
import Transport from 'winston-transport';
import { REDACTED } from './redact.js';
import { requestContext } from './request-context.js';
import {
  buildWinstonOptions,
  contextFormat,
  redactFormat,
} from './winston.config.js';

class Capture extends Transport {
  readonly lines: Record<string, unknown>[] = [];
  override log(info: Record<string, unknown>, next: () => void): void {
    this.lines.push(info);
    next();
  }
}

describe('winston configuration', () => {
  it('injects correlation ids and redacts secrets in every line', () => {
    const capture = new Capture();
    const logger = winston.createLogger({
      format: winston.format.combine(contextFormat(), redactFormat()),
      transports: [capture],
    });
    requestContext.run(
      { requestId: 'req-1', jobId: 'job-9', scanId: 'scan-3' },
      () => {
        logger.info('connecting to redis://:hunter2@redis:6379', {
          password: 'p',
          domain: 'example.com',
        });
      },
    );
    expect(capture.lines[0]).toMatchObject({
      requestId: 'req-1',
      jobId: 'job-9',
      scanId: 'scan-3',
      password: REDACTED,
      domain: 'example.com',
      message: `connecting to redis://:${REDACTED}@redis:6379`,
    });
  });

  it('uses JSON + service metadata in json mode and adds a 31-day rotating file when enabled', () => {
    const options = buildWinstonOptions({
      env: 'production',
      log: {
        level: 'warn',
        format: 'json',
        toFile: true,
        dir: join(tmpdir(), 'fuzzer-scanner-test-logs'),
      },
    });
    expect(options.level).toBe('warn');
    expect(options.defaultMeta).toEqual({
      service: 'fuzzer-scanner',
      env: 'production',
    });
    const transports = options.transports as winston.transport[];
    expect(transports).toHaveLength(2);
    expect(
      (transports[1] as unknown as { options: { maxFiles: string } }).options
        .maxFiles,
    ).toBe('31d');
  });

  it('keeps the dev console free of repeated metadata', () => {
    const options = buildWinstonOptions({
      env: 'development',
      log: { level: 'info', format: 'pretty', toFile: false, dir: 'logs' },
    });
    expect(options.defaultMeta).toBeUndefined();
    expect(options.transports as winston.transport[]).toHaveLength(1);
  });
});
