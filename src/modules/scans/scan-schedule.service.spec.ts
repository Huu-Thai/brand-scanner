import type { Queue } from 'bullmq';
import type { OriginalDomainsQuery } from '../original-domains/original-domains.query.js';
import { ScanScheduleService } from './scan-schedule.service.js';

function setup(existingKeys: string[] = []) {
  const queue = {
    upsertJobScheduler: vi.fn(async () => ({})),
    removeJobScheduler: vi.fn(async () => true),
    getJobSchedulers: vi.fn(async () => existingKeys.map((key) => ({ key }))),
  };
  const originals = {
    findScheduled: vi.fn(async () => [
      { id: 'od-1', scanSchedule: '0 2 * * *' },
    ]),
  } as unknown as OriginalDomainsQuery;
  return {
    queue,
    service: new ScanScheduleService(queue as unknown as Queue, originals),
  };
}

describe('ScanScheduleService', () => {
  it('upserts a UTC job scheduler for active domains with a cron', async () => {
    const { queue, service } = setup();
    await service.sync({
      id: 'od-1',
      isActive: true,
      scanSchedule: '0 2 * * *',
    });
    expect(queue.upsertJobScheduler).toHaveBeenCalledWith(
      'schedule-od-1',
      { pattern: '0 2 * * *', tz: 'UTC' },
      expect.objectContaining({
        name: 'scheduled-scan',
        data: { originalDomainId: 'od-1' },
      }),
    );
  });

  it.each([
    [{ isActive: false, scanSchedule: '0 2 * * *' }],
    [{ isActive: true, scanSchedule: null }],
    [{ isActive: true, scanSchedule: '0 2 * * *', deleted: true }],
  ])('removes the scheduler for %o', async (state) => {
    const { queue, service } = setup();
    await service.sync({ id: 'od-1', ...state });
    expect(queue.removeJobScheduler).toHaveBeenCalledWith('schedule-od-1');
    expect(queue.upsertJobScheduler).not.toHaveBeenCalled();
  });

  it('reconciles: upserts wanted schedulers and removes orphans', async () => {
    const { queue, service } = setup(['schedule-od-1', 'schedule-deleted']);
    expect(await service.reconcile()).toEqual({ upserted: 1, removed: 1 });
    expect(queue.removeJobScheduler).toHaveBeenCalledWith('schedule-deleted');
  });
});
