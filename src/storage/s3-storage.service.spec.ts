import {
  DeleteObjectsCommand,
  HeadBucketCommand,
  PutObjectCommand,
} from '@aws-sdk/client-s3';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/configuration.js';
import { S3StorageService } from './s3-storage.service.js';

function setup(sse?: string) {
  const config = {
    get: () => ({
      serverSideEncryption: sse,
      endpoint: 'http://minio:9000',
      region: 'us-east-1',
      bucket: 'fuzzer-screenshots',
      accessKeyId: 'id',
      secretAccessKey: 'secret',
      forcePathStyle: true,
      signedUrlTtl: 300,
    }),
  } as unknown as ConfigService<AppConfig, true>;
  const service = new S3StorageService(config);
  const send = vi.spyOn(service.client, 'send');
  return { service, send };
}

describe('S3StorageService', () => {
  it('uploads with content type and, when configured, an explicit SSE header', async () => {
    const plain = setup();
    plain.send.mockResolvedValue({} as never);
    await plain.service.putObject('k', Buffer.from('png'), 'image/png');
    expect(
      (plain.send.mock.calls[0][0] as PutObjectCommand).input
        .ServerSideEncryption,
    ).toBeUndefined();

    const { service, send } = setup('AES256');
    send.mockResolvedValue({} as never);
    await service.putObject(
      'screenshots/a/b/c.png',
      Buffer.from('png'),
      'image/png',
    );
    const cmd = send.mock.calls[0][0] as PutObjectCommand;
    expect(cmd).toBeInstanceOf(PutObjectCommand);
    expect(cmd.input).toMatchObject({
      Bucket: 'fuzzer-screenshots',
      Key: 'screenshots/a/b/c.png',
      ContentType: 'image/png',
      ServerSideEncryption: 'AES256',
    });
  });

  it('deletes in batches of 1000 and reports failures', async () => {
    const { service, send } = setup();
    send.mockImplementation(async (cmd) => {
      const keys = (cmd as DeleteObjectsCommand).input.Delete!.Objects!.map(
        (o) => o.Key!,
      );
      return {
        Deleted: keys.slice(1).map((Key) => ({ Key })),
        Errors: [{ Key: keys[0] }],
      } as never;
    });
    const keys = Array.from({ length: 1500 }, (_, i) => `k${i}`);
    const result = await service.deleteObjects(keys);
    expect(send).toHaveBeenCalledTimes(2);
    expect(result.failed).toEqual(['k0', 'k1000']);
    expect(result.deleted).toHaveLength(1498);
  });

  it('pings with HeadBucket', async () => {
    const { service, send } = setup();
    send.mockResolvedValue({} as never);
    await service.ping();
    expect(send.mock.calls[0][0]).toBeInstanceOf(HeadBucketCommand);
  });

  it('creates presigned GET urls that expire', async () => {
    const { service } = setup();
    const url = await service.getSignedUrl('screenshots/x.png');
    expect(url).toContain('fuzzer-screenshots/screenshots/x.png');
    expect(url).toContain('X-Amz-Expires=300');
  });
});
