import { CronExpressionParser } from 'cron-parser';
import { registerDecorator, type ValidationOptions } from 'class-validator';

/** Accepts standard 5-field cron (minute precision) — the format BullMQ job schedulers use. */
export function isValidCron(value: unknown): boolean {
  if (typeof value !== 'string' || value.trim().split(/\s+/).length !== 5)
    return false;
  try {
    CronExpressionParser.parse(value, { tz: 'UTC' });
    return true;
  } catch {
    return false;
  }
}

export function IsCron(options?: ValidationOptions): PropertyDecorator {
  return (target, propertyName) =>
    registerDecorator({
      name: 'isCron',
      target: target.constructor,
      propertyName: propertyName as string,
      options: {
        message:
          '$property must be a 5-field cron expression, e.g. "0 2 * * *"',
        ...options,
      },
      validator: { validate: isValidCron },
    });
}
