import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';

/**
 * Status code of the first response for `url` (no redirect following, TLS errors ignored —
 * look-alike sites often have broken certificates). WebDriver does not expose the HTTP
 * status, so this lightweight probe complements the browser capture. Null when unreachable.
 */
export function probeStatus(
  url: string,
  timeoutMs = 8_000,
): Promise<number | null> {
  return new Promise((resolve) => {
    try {
      const fn = url.startsWith('https:') ? httpsRequest : httpRequest;
      const req = fn(
        url,
        {
          method: 'GET',
          rejectUnauthorized: false,
          timeout: timeoutMs,
          headers: { 'user-agent': 'Mozilla/5.0 (fuzzer-scanner)' },
        },
        (res) => {
          resolve(res.statusCode ?? null);
          res.destroy();
        },
      );
      req.on('timeout', () => req.destroy());
      req.on('error', () => resolve(null));
      req.end();
    } catch {
      resolve(null);
    }
  });
}
