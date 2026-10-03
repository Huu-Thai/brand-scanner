import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { FuzzerService } from './fuzzer.service.js';

/**
 * Parity with the production reference implementation. Fingerprints were recorded by running
 * Reporting's unmodified fuzzer on the same dictionaries; output order matters (sha256Ordered),
 * so this pins both content and ordering.
 */
const fixture = JSON.parse(
  readFileSync(
    new URL('./__fixtures__/reference-fingerprints.json', import.meta.url),
    'utf8',
  ),
) as Record<
  string,
  { total: number; byFuzzer: Record<string, number>; sha256Ordered: string }
>;

describe('DnstwistFuzzer parity with Reporting', () => {
  const service = new FuzzerService();
  beforeAll(() => service.onModuleInit());

  const domains = Object.keys(fixture).filter((k) => !k.startsWith('_'));

  it.each(domains)('%s matches the reference fingerprint', (domain) => {
    const perms = service.generate(domain, { includeOriginal: true });
    const byFuzzer: Record<string, number> = {};
    for (const p of perms) byFuzzer[p.fuzzer] = (byFuzzer[p.fuzzer] ?? 0) + 1;
    const sha = createHash('sha256')
      .update(perms.map((p) => `${p.fuzzer}\t${p.domain}`).join('\n'))
      .digest('hex');

    expect({
      total: perms.length,
      byFuzzer: Object.fromEntries(Object.entries(byFuzzer).sort()),
    }).toEqual({
      total: fixture[domain].total,
      byFuzzer: fixture[domain].byFuzzer,
    });
    expect(sha).toBe(fixture[domain].sha256Ordered);
  });
});
