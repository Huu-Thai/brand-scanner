import { ALL_QUEUES } from '../queue/queue.constants.js';
import { SystemController } from './system.controller.js';

describe('SystemController', () => {
  it('returns service metadata and the calling key name', () => {
    const info = new SystemController().info({
      name: 'ci-reader',
      scope: 'read',
      actor: 'ci-reader',
    });
    expect(info).toMatchObject({
      name: 'fuzzer-scanner',
      caller: 'ci-reader',
      queues: ALL_QUEUES,
    });
    expect(info.uptimeSeconds).toBeGreaterThanOrEqual(0);
  });
});
