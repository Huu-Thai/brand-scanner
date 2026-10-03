import { NotFoundException } from '@nestjs/common';
import { ScannedDomainsController } from './scanned-domains.controller.js';

const principal = {
  name: 'manage-feed',
  scope: 'write' as const,
  actor: 'ana@x',
};

function setup() {
  const read = {
    findOne: vi.fn(async (id: string) => ({ id })),
    findAll: vi.fn(),
  };
  const service = {
    changeStatus: vi.fn(async (ids: string[]) => ({
      changed: ids.length,
      unchanged: 0,
    })),
    updateTags: vi.fn(async (ids: string[]) => ids.length),
    softDelete: vi.fn(async (id: string) => id === 'a'),
  };
  const query = {
    getForEnrichment: vi.fn(async (id: string) =>
      id === 'a' ? { domain: 'a.com' } : null,
    ),
  };
  async function* chunks(): AsyncGenerator<string> {
    yield 'x,y\r\n';
    yield '1,2\r\n';
  }
  const exporter = {
    contentType: vi.fn(() => 'text/csv; charset=utf-8'),
    stream: vi.fn(chunks),
  };
  const rescans = { enqueue: vi.fn(async () => 'job-1') };
  const ctrl = new ScannedDomainsController(
    read as never,
    service as never,
    query as never,
    exporter as never,
    rescans as never,
  );
  return { ctrl, read, service, exporter, rescans };
}

describe('ScannedDomainsController', () => {
  it('bulk applies status and tags as the acting user', async () => {
    const { ctrl, service } = setup();
    const result = await ctrl.bulk(
      {
        ids: ['a', 'b'],
        status: 'CONFIRMED_THREAT',
        addTags: ['vip'],
      } as never,
      principal,
    );
    expect(result).toEqual({ statusChanged: 2, tagsUpdated: 2 });
    expect(service.changeStatus).toHaveBeenCalledWith(
      ['a', 'b'],
      'CONFIRMED_THREAT',
      { source: 'manual', actor: 'ana@x' },
    );
    expect(service.updateTags).toHaveBeenCalledWith(
      ['a', 'b'],
      { add: ['vip'], remove: undefined },
      'ana@x',
    );
  });

  it('PATCH only touches what was sent and returns the fresh row', async () => {
    const { ctrl, service, read } = setup();
    expect(
      await ctrl.update('a', { removeTags: ['x'] } as never, principal),
    ).toEqual({ id: 'a' });
    expect(service.changeStatus).not.toHaveBeenCalled();
    expect(read.findOne).toHaveBeenCalledTimes(2); // 404 check, then reload
  });

  it('DELETE 404s unknown look-alikes', async () => {
    const { ctrl } = setup();
    await expect(ctrl.remove('a', principal)).resolves.toBeUndefined();
    await expect(ctrl.remove('b', principal)).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });

  it('rescan queues a job for existing look-alikes only', async () => {
    const { ctrl, rescans } = setup();
    expect(await ctrl.rescan('a', principal)).toEqual({
      queued: true,
      jobId: 'job-1',
    });
    expect(rescans.enqueue).toHaveBeenCalledWith({
      scannedDomainId: 'a',
      domain: 'a.com',
      actor: 'ana@x',
    });
    await expect(ctrl.rescan('b', principal)).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });

  it('streams the export as a download', async () => {
    const { ctrl } = setup();
    const headers: Record<string, string> = {};
    const written: string[] = [];
    const res = {
      setHeader: (k: string, v: string) => (headers[k] = v),
      write: (c: string) => written.push(c) > 0,
      end: vi.fn(),
      destroy: vi.fn(),
    };
    await ctrl.export({ format: 'csv' } as never, res as never);
    expect(headers['content-type']).toMatch(/text\/csv/);
    expect(headers['content-disposition']).toMatch(
      /^attachment; filename="lookalikes-.+\.csv"$/,
    );
    expect(written.join('')).toBe('x,y\r\n1,2\r\n');
    expect(res.end).toHaveBeenCalled();
  });

  it('aborts the response when the export fails mid-stream', async () => {
    const { ctrl, exporter } = setup();
    exporter.stream.mockImplementation(async function* () {
      yield 'header\r\n';
      throw new Error('db gone');
    });
    const res = {
      setHeader: vi.fn(),
      write: vi.fn(() => true),
      end: vi.fn(),
      destroy: vi.fn(),
    };
    await ctrl.export({ format: 'csv' } as never, res as never);
    expect(res.end).not.toHaveBeenCalled();
    expect(res.destroy).toHaveBeenCalledWith(expect.any(Error));
  });
});
