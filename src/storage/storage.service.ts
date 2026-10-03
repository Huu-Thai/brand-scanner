export interface StoredObject {
  key: string;
  lastModified: Date;
  size: number;
}

/** Object storage abstraction (PLAN.md §6b). S3StorageService is the only implementation. */
export abstract class StorageService {
  abstract readonly bucket: string;
  abstract putObject(
    key: string,
    body: Buffer,
    contentType: string,
  ): Promise<void>;
  abstract getSignedUrl(key: string, ttlSeconds?: number): Promise<string>;
  abstract deleteObjects(
    keys: string[],
  ): Promise<{ deleted: string[]; failed: string[] }>;
  /** Pages of objects under `prefix` (≤ 1000 per page), for the orphan sweep. */
  abstract listObjects(
    prefix: string,
  ): AsyncGenerator<StoredObject[], void, undefined>;
  abstract ping(): Promise<void>;
}
