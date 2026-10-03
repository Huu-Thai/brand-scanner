import { requestContext } from './request-context.js';

describe('requestContext', () => {
  it('scopes values to the async call chain and allows enrichment', async () => {
    expect(requestContext.get()).toBeUndefined();
    await requestContext.run({ requestId: 'r1' }, async () => {
      await Promise.resolve();
      requestContext.set({ scanId: 's1' });
      expect(requestContext.get()).toEqual({ requestId: 'r1', scanId: 's1' });
    });
    expect(requestContext.get()).toBeUndefined();
  });

  it('ignores set() outside of a context', () => {
    expect(() => requestContext.set({ jobId: 'j' })).not.toThrow();
  });
});
