import {
  SCAN_PROCESSORS,
  ScansWorkerModule,
} from './modules/scans/scans-worker.module.js';
import { WorkerModule } from './worker.module.js';

describe('worker module selection', () => {
  it('registers every scan processor when WORKER_QUEUES is empty', () => {
    expect(ScansWorkerModule.forQueues([]).providers).toEqual(
      Object.values(SCAN_PROCESSORS),
    );
  });

  it('registers only the requested processors', () => {
    expect(ScansWorkerModule.forQueues(['dns-resolve']).providers).toEqual([
      SCAN_PROCESSORS['dns-resolve'],
    ]);
  });

  it('rejects unknown queue names at boot', () => {
    expect(() => WorkerModule.forQueues(['dns-reslove'])).toThrow(
      /unknown queues: dns-reslove/,
    );
  });
});
