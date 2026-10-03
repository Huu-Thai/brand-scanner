import { createRequire } from 'node:module';

interface WordsNinjaInstance {
  loadDictionary(): Promise<void>;
  splitSentence(text: string): string[];
}

const require = createRequire(import.meta.url);

/**
 * wordninja-style splitter used by the `englishsplit` and `wordswap` techniques
 * ("paypalsecure" → ["paypal", "secure"]). Same library as Reporting, for parity.
 */
export async function createWordSplitter(): Promise<
  (text: string) => string[]
> {
  const WordsNinja = require('wordsninja') as new () => WordsNinjaInstance;
  const instance = new WordsNinja();
  await instance.loadDictionary();
  return (text) => instance.splitSentence(text);
}
