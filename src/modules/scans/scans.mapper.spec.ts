import type { ScanModel } from '../../database/generated/prisma/models.js';
import { toScanDto } from './scans.mapper.js';

const base = {
  permutationsTotal: 0,
  resolvedCount: 0,
  status: 'QUEUED',
  options: null,
} as unknown as ScanModel;

describe('toScanDto', () => {
  it('computes progress to one decimal and caps at 100', () => {
    expect(
      toScanDto({ ...base, permutationsTotal: 3, resolvedCount: 1 })
        .progressPercent,
    ).toBe(33.3);
    expect(
      toScanDto({ ...base, permutationsTotal: 2, resolvedCount: 5 })
        .progressPercent,
    ).toBe(100);
  });

  it('reports 100 for a completed scan with no permutations, 0 otherwise', () => {
    expect(
      toScanDto({ ...base, status: 'COMPLETED' } as ScanModel).progressPercent,
    ).toBe(100);
    expect(toScanDto(base).progressPercent).toBe(0);
    expect(toScanDto(base).options).toEqual({});
  });
});
