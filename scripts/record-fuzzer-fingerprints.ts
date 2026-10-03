/**
 * Re-records src/modules/fuzzer/__fixtures__/reference-fingerprints.json from a REFERENCE
 * fuzzer implementation (by default Reporting's), using this repo's dictionaries.
 *
 *   REFERENCE_FUZZER=../Reporting/src/modules/wsd-scanner-worker/utils/dnstwist-fuzzer.util.ts \
 *     npx tsx scripts/record-fuzzer-fingerprints.ts
 *
 * Only re-record when the reference itself changed on purpose — the parity test exists to
 * catch accidental drift in our port.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const reference = resolve(
  process.env.REFERENCE_FUZZER ??
    '../Reporting/src/modules/wsd-scanner-worker/utils/dnstwist-fuzzer.util.ts',
);
const { DnstwistFuzzer } = await import(pathToFileURL(reference).href);
const require = createRequire(import.meta.url);
const WordsNinja = require('wordsninja');

const dict = (f: string) =>
  readFileSync(`src/modules/fuzzer/dictionaries/${f}`, 'utf8')
    .split('\n')
    .map((l: string) => l.trim())
    .filter((l: string) => l && !l.startsWith('#') && !l.startsWith('//'));

const ninja = new WordsNinja();
await ninja.loadDictionary();

const out: Record<string, unknown> = {
  _source: `${reference} + repo dictionaries + wordsninja, recorded ${new Date().toISOString().slice(0, 10)}`,
};
for (const domain of [
  'google.com',
  'example.co.uk',
  'bank-secure.de',
  'login.paypal.com',
  'münchen.info',
]) {
  const perms: { fuzzer: string; domain: string }[] = new DnstwistFuzzer(
    domain,
    dict('english.dict'),
    dict('abused_tlds.dict'),
    dict('wordlist.txt'),
    dict('tlds.dict'),
    (s: string) => ninja.splitSentence(s),
  ).generate();
  const byFuzzer: Record<string, number> = {};
  for (const p of perms) byFuzzer[p.fuzzer] = (byFuzzer[p.fuzzer] ?? 0) + 1;
  out[domain] = {
    total: perms.length,
    byFuzzer: Object.fromEntries(Object.entries(byFuzzer).sort()),
    sha256Ordered: createHash('sha256')
      .update(perms.map((p) => `${p.fuzzer}\t${p.domain}`).join('\n'))
      .digest('hex'),
  };
}
writeFileSync(
  'src/modules/fuzzer/__fixtures__/reference-fingerprints.json',
  JSON.stringify(out, null, 2) + '\n',
);
console.log(
  'Recorded fingerprints for',
  Object.keys(out).length - 1,
  'domains',
);
