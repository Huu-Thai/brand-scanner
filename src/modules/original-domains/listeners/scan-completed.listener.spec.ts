import {
  ScanFinishedEvent,
  SCAN_EVENTS,
} from '../../scans/events/scan.events.js';
import type { OriginalDomainsService } from '../original-domains.service.js';
import { ScanCompletedListener } from './scan-completed.listener.js';

describe('ScanCompletedListener', () => {
  it('records lastScannedAt and swallows failures', async () => {
    const service = { markScanned: vi.fn(async () => undefined) };
    const listener = new ScanCompletedListener(
      service as unknown as OriginalDomainsService,
    );
    const event = new ScanFinishedEvent(
      SCAN_EVENTS.COMPLETED,
      's',
      'od-1',
      true,
    );
    await listener.onScanCompleted(event);
    expect(service.markScanned).toHaveBeenCalledWith('od-1', event.occurredAt);
    service.markScanned.mockRejectedValueOnce(new Error('db'));
    await expect(listener.onScanCompleted(event)).resolves.toBeUndefined();
  });
});
