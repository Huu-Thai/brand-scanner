import { constraintFromMeta, FOREIGN_KEYS } from './constraints.js';

describe('constraintFromMeta', () => {
  it('reads the Prisma 7 driver-adapter shape', () => {
    expect(
      constraintFromMeta({
        driverAdapterError: {
          cause: { constraint: { index: 'fk_scans_original_domain_id' } },
        },
      }),
    ).toBe('fk_scans_original_domain_id');
    expect(
      constraintFromMeta({
        driverAdapterError: { cause: { constraint: 'uq_x' } },
      }),
    ).toBe('uq_x');
  });

  it('falls back to a top-level constraint field, else undefined', () => {
    expect(constraintFromMeta({ constraint: 'fk_a' })).toBe('fk_a');
    expect(constraintFromMeta(undefined)).toBeUndefined();
    expect(constraintFromMeta({})).toBeUndefined();
  });

  it('documents every foreign key (9 core + 5 alerting + 1 brand reference)', () => {
    // The migration e2e test asserts the exact set against the database.
    expect(Object.keys(FOREIGN_KEYS)).toHaveLength(15);
  });
});
