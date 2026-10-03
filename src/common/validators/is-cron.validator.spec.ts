import { validate } from 'class-validator';
import { IsCron, isValidCron } from './is-cron.validator.js';

class Dto {
  @IsCron()
  schedule: unknown;
}

describe('IsCron', () => {
  it.each(['0 2 * * *', '*/15 * * * *', '0 3 * * 1-5'])('accepts %s', (expr) =>
    expect(isValidCron(expr)).toBe(true),
  );

  it.each(['', '0 2 * *', '0 0 2 * * *', '61 * * * *', 'every day', 42])(
    'rejects %s',
    (expr) => expect(isValidCron(expr)).toBe(false),
  );

  it('reports a helpful message through class-validator', async () => {
    const dto = Object.assign(new Dto(), { schedule: 'nope' });
    const [error] = await validate(dto);
    expect(Object.values(error.constraints!)[0]).toMatch(/5-field cron/);
  });
});
