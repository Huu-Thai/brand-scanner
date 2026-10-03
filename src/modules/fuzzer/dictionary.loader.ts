import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Bundled dictionaries (copied from Reporting/dictionaries; shipped to dist via nest-cli assets). */
export const DICTIONARY_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  'dictionaries',
);

export interface Dictionaries {
  /** english.dict — brand-adjacent phishing words for the `dictionary` technique. */
  dictionary: string[];
  /** abused_tlds.dict — targets of the `tld-swap` technique. */
  tldDictionary: string[];
  /** wordlist.txt — words for `wordaddition`. */
  wordlist: string[];
  /** tlds.dict — small regional list for the `fuzzerwithtld` cross-product. */
  fuzzerTlds: string[];
}

/** Same parsing as Reporting's readLines(): trim, drop blanks and `#` / `//` comments. */
export function parseLines(content: string): string[] {
  return content
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#') && !l.startsWith('//'));
}

export async function loadDictionaries(
  dir = DICTIONARY_DIR,
): Promise<Dictionaries> {
  const read = async (file: string) =>
    parseLines(await readFile(join(dir, file), 'utf8'));
  const [dictionary, tldDictionary, wordlist, fuzzerTlds] = await Promise.all([
    read('english.dict'),
    read('abused_tlds.dict'),
    read('wordlist.txt'),
    read('tlds.dict'),
  ]);
  return { dictionary, tldDictionary, wordlist, fuzzerTlds };
}
