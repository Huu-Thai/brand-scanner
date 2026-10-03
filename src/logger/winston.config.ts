import { utilities as nestWinston } from 'nest-winston';
import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import type { AppConfig } from '../config/configuration.js';
import { isSensitiveKey, REDACTED, redact } from './redact.js';
import { requestContext } from './request-context.js';

const { combine, timestamp, errors, json, ms } = winston.format;

/** Masks secrets in the message and every metadata field. */
export const redactFormat = winston.format((info) => {
  for (const key of Object.keys(info)) {
    if (key === 'level') continue;
    info[key] = isSensitiveKey(key) ? REDACTED : redact(info[key]);
  }
  for (const sym of Object.getOwnPropertySymbols(info)) {
    const v = (info as Record<symbol, unknown>)[sym];
    if (typeof v === 'string')
      (info as Record<symbol, unknown>)[sym] = redact(v);
  }
  return info;
});

/** Injects requestId / jobId / queue / scanId from AsyncLocalStorage. */
export const contextFormat = winston.format((info) => {
  const ctx = requestContext.get();
  if (ctx) {
    for (const [key, value] of Object.entries(ctx)) {
      if (value !== undefined && info[key] === undefined) info[key] = value;
    }
  }
  return info;
});

export function buildWinstonOptions(
  config: Pick<AppConfig, 'log' | 'env'>,
  appName = 'fuzzer-scanner',
): winston.LoggerOptions {
  const base = [
    errors({ stack: true }),
    timestamp(),
    contextFormat(),
    redactFormat(),
  ];

  const console =
    config.log.format === 'json'
      ? new winston.transports.Console({ format: combine(...base, json()) })
      : new winston.transports.Console({
          format: combine(
            ...base,
            ms(),
            nestWinston.format.nestLike(appName, {
              colors: true,
              prettyPrint: true,
            }),
          ),
        });

  const transports: winston.transport[] = [console];
  if (config.log.toFile) {
    transports.push(
      new DailyRotateFile({
        dirname: config.log.dir,
        filename: `${appName}-%DATE%.log`,
        datePattern: 'YYYY-MM-DD',
        zippedArchive: true,
        maxFiles: '31d', // matches the 31-day data-retention policy
        format: combine(...base, json()),
      }),
    );
  }

  return {
    level: config.log.level,
    // service/env tag JSON lines for the log stack; omitted from the dev console to keep it readable.
    defaultMeta:
      config.log.format === 'json'
        ? { service: appName, env: config.env }
        : undefined,
    transports,
    exitOnError: false,
  };
}
