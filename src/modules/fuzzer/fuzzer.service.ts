import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { type Dictionaries, loadDictionaries } from './dictionary.loader.js';
import { DnstwistFuzzer, type Permutation } from './dnstwist-fuzzer.js';
import { type FuzzerName, ORIGINAL_FUZZER } from './fuzzer.constants.js';
import { createWordSplitter } from './word-splitter.js';

export interface GenerateOptions {
  /** Restrict output to these techniques; empty/undefined = all. */
  fuzzers?: FuzzerName[];
  /** Include the `*original` baseline row (default false — the brand's own domain is never a look-alike). */
  includeOriginal?: boolean;
}

/** Loads dictionaries + word splitter once per process and generates permutations. */
@Injectable()
export class FuzzerService implements OnModuleInit {
  private readonly logger = new Logger(FuzzerService.name);
  private dictionaries?: Dictionaries;
  private wordSplit?: (text: string) => string[];

  async onModuleInit(): Promise<void> {
    const started = Date.now();
    [this.dictionaries, this.wordSplit] = await Promise.all([
      loadDictionaries(),
      createWordSplitter(),
    ]);
    this.logger.log(
      `Fuzzer ready in ${Date.now() - started}ms (${this.dictionaries.tldDictionary.length} swap TLDs, ${this.dictionaries.dictionary.length} words)`,
    );
  }

  generate(domain: string, options: GenerateOptions = {}): Permutation[] {
    if (!this.dictionaries || !this.wordSplit) {
      throw new Error('FuzzerService used before initialisation');
    }
    const { dictionary, tldDictionary, wordlist, fuzzerTlds } =
      this.dictionaries;
    const all = new DnstwistFuzzer(
      domain,
      dictionary,
      tldDictionary,
      wordlist,
      fuzzerTlds,
      this.wordSplit,
    ).generate();

    const allowed = options.fuzzers?.length
      ? new Set<string>(options.fuzzers)
      : null;
    return all.filter((p) =>
      p.fuzzer === ORIGINAL_FUZZER
        ? options.includeOriginal === true
        : !allowed || allowed.has(p.fuzzer),
    );
  }
}
