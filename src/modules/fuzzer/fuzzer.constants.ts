/** Every technique label `DnstwistFuzzer.generate()` can emit (except the `*original` baseline). */
export const FUZZERS = [
  'addition',
  'bitsquatting',
  'cyrillic',
  'dictionary',
  'englishsplit',
  'fuzzerwithtld',
  'homoglyph',
  'hyphenation',
  'insertion',
  'omission',
  'plural',
  'repetition',
  'replacement',
  'subdomain',
  'tld-swap',
  'transposition',
  'various',
  'vowel_swap',
  'wordaddition',
  'wordswap',
] as const;

export type FuzzerName = (typeof FUZZERS)[number];

export const ORIGINAL_FUZZER = '*original';
