import sharp from 'sharp';

export interface ImageInfo {
  width: number;
  height: number;
  sizeBytes: number;
  /** 64-bit difference hash (dHash) as 16 hex chars — near-identical pages have close hashes. */
  perceptualHash: string;
}

/** dHash: 9×8 greyscale thumbnail, one bit per "left pixel brighter than right pixel". */
export async function analyzeImage(png: Buffer): Promise<ImageInfo> {
  const meta = await sharp(png).metadata();
  const pixels = await sharp(png)
    .greyscale()
    .resize(9, 8, { fit: 'fill' })
    .raw()
    .toBuffer();
  let bits = 0n;
  for (let y = 0; y < 8; y++) {
    for (let x = 0; x < 8; x++) {
      bits =
        (bits << 1n) | (pixels[y * 9 + x] > pixels[y * 9 + x + 1] ? 1n : 0n);
    }
  }
  return {
    width: meta.width ?? 0,
    height: meta.height ?? 0,
    sizeBytes: png.length,
    perceptualHash: bits.toString(16).padStart(16, '0'),
  };
}

/** Hamming distance between two dHashes (0 = identical, 64 = opposite). */
export function hashDistance(a: string, b: string): number {
  let x = BigInt(`0x${a}`) ^ BigInt(`0x${b}`);
  let n = 0;
  while (x) {
    n += Number(x & 1n);
    x >>= 1n;
  }
  return n;
}
