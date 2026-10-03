import type { Queue } from 'bullmq';
import {
  OriginalDomainCreatedEvent,
  OriginalDomainDeletedEvent,
  OriginalDomainUpdatedEvent,
} from '../../original-domains/events/original-domain.events.js';
import { ScanCreatedEvent } from '../events/scan.events.js';
import type { ScanScheduleService } from '../scan-schedule.service.js';
import type { ScansService } from '../scans.service.js';
import { ScanLifecycleListener } from './scan-lifecycle.listener.js';

const snapshot = {
  id: 'od-1',
  domain: 'example.com',
  isActive: true,
  scanSchedule: '0 2 * * *',
};

function setup() {
  const queue = { add: vi.fn(async () => ({})) };
  const scans = {
    fail: vi.fn(async () => null),
    cancel: vi.fn(async () => ({})),
    activeScanIds: vi.fn(async () => ['scan-1', 'scan-2']),
  };
  const schedules = { sync: vi.fn(async () => undefined) };
  const listener = new ScanLifecycleListener(
    queue as unknown as Queue,
    scans as unknown as ScansService,
    schedules as unknown as ScanScheduleService,
  );
  return { queue, scans, schedules, listener };
}

describe('ScanLifecycleListener', () => {
  it('enqueues orchestration with a deterministic job id', async () => {
    const t = setup();
    await t.listener.onScanCreated(
      new ScanCreatedEvent('scan-1', 'od-1', 'API'),
    );
    expect(t.queue.add).toHaveBeenCalledWith(
      'orchestrate',
      { scanId: 'scan-1' },
      { jobId: 'orchestrate-scan-1', attempts: 3 },
    );
  });

  it('fails the scan if it cannot be enqueued (frees the active-scan slot)', async () => {
    const t = setup();
    t.queue.add.mockRejectedValue(new Error('redis down'));
    await t.listener.onScanCreated(
      new ScanCreatedEvent('scan-1', 'od-1', 'API'),
    );
    expect(t.scans.fail).toHaveBeenCalledWith(
      'scan-1',
      'Could not enqueue scan job',
    );
  });

  it('syncs schedules on create, and on update only when schedule/active changed', async () => {
    const t = setup();
    await t.listener.onOriginalDomainSaved(
      new OriginalDomainCreatedEvent(snapshot),
    );
    await t.listener.onOriginalDomainSaved(
      new OriginalDomainUpdatedEvent(snapshot, ['label']),
    );
    await t.listener.onOriginalDomainSaved(
      new OriginalDomainUpdatedEvent(snapshot, ['scanSchedule']),
    );
    expect(t.schedules.sync).toHaveBeenCalledTimes(2);
  });

  it('on delete: removes the schedule and cancels in-flight scans', async () => {
    const t = setup();
    t.scans.cancel.mockRejectedValueOnce(new Error('already done'));
    await t.listener.onOriginalDomainDeleted(
      new OriginalDomainDeletedEvent(snapshot),
    );
    expect(t.schedules.sync).toHaveBeenCalledWith({
      ...snapshot,
      deleted: true,
    });
    expect(t.scans.cancel).toHaveBeenCalledTimes(2);
  });

  it('never throws when schedule sync fails', async () => {
    const t = setup();
    t.schedules.sync.mockRejectedValue(new Error('redis down'));
    await expect(
      t.listener.onOriginalDomainSaved(
        new OriginalDomainCreatedEvent(snapshot),
      ),
    ).resolves.toBeUndefined();
  });
});
