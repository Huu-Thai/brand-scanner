import { BadRequestException, NotFoundException } from '@nestjs/common';
import type { Response } from 'express';
import type { OriginalDomainsQuery } from '../original-domains/original-domains.query.js';
import { ScansController } from './scans.controller.js';
import type { ScansService } from './scans.service.js';

const scan = {
  id: 'scan-1',
  originalDomainId: 'od-1',
  status: 'QUEUED',
  options: {},
  permutationsTotal: 0,
  resolvedCount: 0,
};

function setup(created = true) {
  const scans = {
    create: vi.fn(async () => ({ scan, created })),
    get: vi.fn(async () => scan),
    cancel: vi.fn(async () => scan),
    findAll: vi.fn(),
  };
  const originals = {
    findByDomain: vi.fn(async (d: string) =>
      d === 'example.com' ? { id: 'od-1' } : null,
    ),
  };
  const res = { status: vi.fn(), setHeader: vi.fn() } as unknown as Response;
  return {
    scans,
    res,
    controller: new ScansController(
      scans as unknown as ScansService,
      originals as unknown as OriginalDomainsQuery,
    ),
  };
}

describe('ScansController', () => {
  it('202 + Location for a new scan; resolves `domain` to the original domain id', async () => {
    const t = setup(true);
    const dto = await t.controller.create(
      { domain: 'Example.COM' },
      'key-12345678',
      t.res,
    );
    expect(t.scans.create).toHaveBeenCalledWith(
      expect.objectContaining({
        originalDomainId: 'od-1',
        triggeredBy: 'API',
        idempotencyKey: 'key-12345678',
      }),
    );
    expect(t.res.status).toHaveBeenCalledWith(202);
    expect(t.res.setHeader).toHaveBeenCalledWith(
      'Location',
      '/api/v1/scans/scan-1',
    );
    expect(dto.id).toBe('scan-1');
  });

  it('200 when an in-flight scan is returned', async () => {
    const t = setup(false);
    await t.controller.trigger('od-1', {}, undefined, t.res);
    expect(t.res.status).toHaveBeenCalledWith(200);
  });

  it('validates the Idempotency-Key and the domain', async () => {
    const t = setup();
    await expect(
      t.controller.create({ originalDomainId: 'od-1' }, 'bad key!', t.res),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      t.controller.create({ domain: 'not a domain' }, undefined, t.res),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      t.controller.create({ domain: 'unknown.com' }, undefined, t.res),
    ).rejects.toBeInstanceOf(NotFoundException);
  });

  it('maps scans for get/cancel', async () => {
    const t = setup();
    expect((await t.controller.findOne('scan-1')).progressPercent).toBe(0);
    expect((await t.controller.cancel('scan-1')).id).toBe('scan-1');
  });
});
