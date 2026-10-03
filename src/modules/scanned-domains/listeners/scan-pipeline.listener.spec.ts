import {
  ScanBatchResolvedEvent,
  ScanFinishedEvent,
  SCAN_EVENTS,
} from '../../scans/events/scan.events.js';
import type { ScannedDomainsService } from '../scanned-domains.service.js';
import { ScanPipelineListener } from './scan-pipeline.listener.js';

describe('ScanPipelineListener', () => {
  const service = {
    upsertBatch: vi.fn(async () => ({ inserted: 1, updated: 0 })),
    markUnseenInactive: vi.fn(async () => ['x']),
  };
  const listener = new ScanPipelineListener(
    service as unknown as ScannedDomainsService,
  );

  it('persists resolved batches and returns the result to the awaiting processor', async () => {
    expect(
      await listener.onBatchResolved(
        new ScanBatchResolvedEvent('s', 'od', { 'a.com': 'omission' }, []),
      ),
    ).toEqual({
      inserted: 1,
      updated: 0,
    });
  });

  it('marks unseen domains inactive only after full scans, and never throws', async () => {
    await listener.onScanCompleted(
      new ScanFinishedEvent(SCAN_EVENTS.COMPLETED, 's', 'od', false),
    );
    expect(service.markUnseenInactive).not.toHaveBeenCalled();
    await listener.onScanCompleted(
      new ScanFinishedEvent(SCAN_EVENTS.COMPLETED, 's', 'od', true),
    );
    expect(service.markUnseenInactive).toHaveBeenCalledWith('od', 's');
    service.markUnseenInactive.mockRejectedValueOnce(new Error('db'));
    await expect(
      listener.onScanCompleted(
        new ScanFinishedEvent(SCAN_EVENTS.COMPLETED, 's', 'od', true),
      ),
    ).resolves.toBeUndefined();
  });
});
