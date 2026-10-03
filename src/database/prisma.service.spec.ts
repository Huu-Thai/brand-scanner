import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/configuration.js';
import { PrismaService } from './prisma.service.js';

describe('PrismaService', () => {
  const config = {
    get: () => ({ url: 'postgresql://u:p@localhost:5432/db' }),
  } as unknown as ConfigService<AppConfig, true>;

  it('connects on init and disconnects on destroy', async () => {
    const service = new PrismaService(config);
    const connect = vi.spyOn(service, '$connect').mockResolvedValue(undefined);
    const disconnect = vi
      .spyOn(service, '$disconnect')
      .mockResolvedValue(undefined);
    await service.onModuleInit();
    await service.onModuleDestroy();
    expect(connect).toHaveBeenCalledOnce();
    expect(disconnect).toHaveBeenCalledOnce();
  });
});
