import { chunk, mapWithConcurrency } from './concurrency.js';

describe('mapWithConcurrency', () => {
  it('preserves order and never exceeds the limit', async () => {
    let inFlight = 0;
    let peak = 0;
    const result = await mapWithConcurrency([5, 1, 4, 2, 3], 2, async (n) => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, n));
      inFlight--;
      return n * 10;
    });
    expect(result).toEqual([50, 10, 40, 20, 30]);
    expect(peak).toBe(2);
  });

  it('handles empty input and propagates errors', async () => {
    expect(await mapWithConcurrency([], 3, async () => 1)).toEqual([]);
    await expect(
      mapWithConcurrency([1], 3, async () => Promise.reject(new Error('boom'))),
    ).rejects.toThrow('boom');
  });
});

describe('chunk', () => {
  it('splits into fixed-size chunks with a partial tail', () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
    expect(chunk([], 3)).toEqual([]);
  });
});
