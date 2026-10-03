import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const VERSION = 'v1';

/**
 * AES-256-GCM for secrets stored in the database (alert targets, webhook signing secrets).
 * Format: `v1.<iv>.<tag>.<ciphertext>` (base64url). The key is 32 bytes, given as 64 hex chars
 * or base64. Tampering or a wrong key throws.
 */
export class SecretBox {
  private readonly key: Buffer;

  constructor(key: string) {
    this.key = parseKey(key);
  }

  seal(plaintext: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const data = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    return [VERSION, iv, cipher.getAuthTag(), data]
      .map((p) => (typeof p === 'string' ? p : p.toString('base64url')))
      .join('.');
  }

  open(sealed: string): string {
    const [version, iv, tag, data] = sealed.split('.');
    if (version !== VERSION || !iv || !tag || data === undefined)
      throw new Error('Unrecognised sealed secret');
    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.key,
      Buffer.from(iv, 'base64url'),
    );
    decipher.setAuthTag(Buffer.from(tag, 'base64url'));
    return Buffer.concat([
      decipher.update(Buffer.from(data, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
  }
}

export function parseKey(key: string): Buffer {
  const buf = /^[0-9a-fA-F]{64}$/.test(key)
    ? Buffer.from(key, 'hex')
    : Buffer.from(key, 'base64');
  if (buf.length !== 32)
    throw new Error('Encryption key must be 32 bytes (64 hex chars or base64)');
  return buf;
}
