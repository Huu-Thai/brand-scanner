import {
  DeleteObjectsCommand,
  GetObjectCommand,
  HeadBucketCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/configuration.js';
import { StorageService, type StoredObject } from './storage.service.js';

const DELETE_BATCH = 1000; // S3 DeleteObjects limit

@Injectable()
export class S3StorageService
  extends StorageService
  implements OnModuleDestroy
{
  readonly bucket: string;
  private readonly signedUrlTtl: number;
  private readonly sse?: 'AES256' | 'aws:kms';
  readonly client: S3Client;

  constructor(config: ConfigService<AppConfig, true>) {
    super();
    const s3 = config.get('s3', { infer: true });
    this.bucket = s3.bucket;
    this.signedUrlTtl = s3.signedUrlTtl;
    this.sse = s3.serverSideEncryption;
    this.client = new S3Client({
      region: s3.region,
      endpoint: s3.endpoint,
      forcePathStyle: s3.forcePathStyle,
      credentials: {
        accessKeyId: s3.accessKeyId,
        secretAccessKey: s3.secretAccessKey,
      },
    });
  }

  async putObject(
    key: string,
    body: Buffer,
    contentType: string,
  ): Promise<void> {
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: body,
        ContentType: contentType,
        ...(this.sse ? { ServerSideEncryption: this.sse } : {}),
      }),
    );
  }

  getSignedUrl(key: string, ttlSeconds = this.signedUrlTtl): Promise<string> {
    return getSignedUrl(
      this.client,
      new GetObjectCommand({ Bucket: this.bucket, Key: key }),
      {
        expiresIn: ttlSeconds,
      },
    );
  }

  async deleteObjects(
    keys: string[],
  ): Promise<{ deleted: string[]; failed: string[] }> {
    const deleted: string[] = [];
    const failed: string[] = [];
    for (let i = 0; i < keys.length; i += DELETE_BATCH) {
      const batch = keys.slice(i, i + DELETE_BATCH);
      const res = await this.client.send(
        new DeleteObjectsCommand({
          Bucket: this.bucket,
          Delete: { Objects: batch.map((Key) => ({ Key })), Quiet: false },
        }),
      );
      deleted.push(...(res.Deleted ?? []).map((d) => d.Key!).filter(Boolean));
      failed.push(...(res.Errors ?? []).map((e) => e.Key!).filter(Boolean));
    }
    return { deleted, failed };
  }

  async *listObjects(
    prefix: string,
  ): AsyncGenerator<StoredObject[], void, undefined> {
    let token: string | undefined;
    do {
      const res = await this.client.send(
        new ListObjectsV2Command({
          Bucket: this.bucket,
          Prefix: prefix,
          ContinuationToken: token,
          MaxKeys: 1000,
        }),
      );
      const page = (res.Contents ?? [])
        .filter((o) => o.Key)
        .map((o) => ({
          key: o.Key!,
          lastModified: o.LastModified ?? new Date(0),
          size: o.Size ?? 0,
        }));
      if (page.length) yield page;
      token = res.IsTruncated ? res.NextContinuationToken : undefined;
    } while (token);
  }

  async ping(): Promise<void> {
    await this.client.send(new HeadBucketCommand({ Bucket: this.bucket }));
  }

  onModuleDestroy(): void {
    this.client.destroy();
  }
}
