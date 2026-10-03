/**
 * dnstwist-compatible domain fuzzer.
 *
 * Ported verbatim (algorithms, tables and output order) from Reporting
 * `src/modules/wsd-scanner-worker/utils/dnstwist-fuzzer.util.ts`, which itself mirrors the
 * Python WSD_Worker_API dnstwist Fuzzer. `fuzzer.parity.spec.ts` pins this file to the
 * reference output, so any behavioural change here must be deliberate.
 *
 * Pure: no I/O, no Nest dependencies. Technique methods are public so each can be unit-tested.
 */
import { domainToASCII } from 'node:url';
import { parse as parseTld } from 'tldts';

// ─── Data tables (ported from Python dnstwist) ───────────────────────────────

export const GLYPHS_ASCII: Record<string, string[]> = {
  '0': ['o'],
  '1': ['l', 'i'],
  '3': ['8'],
  '6': ['9'],
  '8': ['3'],
  '9': ['6'],
  b: ['d', 'lb'],
  c: ['e'],
  d: ['b', 'cl', 'dl'],
  e: ['c'],
  g: ['q'],
  h: ['lh'],
  i: ['1', 'l'],
  k: ['lc'],
  l: ['1', 'i'],
  m: ['n', 'nn', 'rn'],
  n: ['m', 'r'],
  o: ['0'],
  q: ['g'],
  u: ['v'],
  v: ['u'],
  w: ['vv'],
  rn: ['m'],
  cl: ['d'],
};

// Matches Python Fuzzer.glyphs_idn_by_tld exactly.
// TLDs mapped to empty objects have NO IDN support — only ASCII glyphs apply.
// TLDs absent from this map fall back to GLYPHS_UNICODE (the full set).
const _NO_IDN: Record<string, string[]> = {};
const _INFO_GLYPHS: Record<string, string[]> = {
  a: ['á', 'ä', 'å', 'ą'],
  c: ['ć', 'č'],
  e: ['é', 'ė', 'ę'],
  i: ['í', 'į'],
  l: ['ł'],
  n: ['ñ', 'ń'],
  o: ['ó', 'ö', 'ø', 'ő'],
  s: ['ś', 'š'],
  u: ['ú', 'ü', 'ū', 'ű', 'ų'],
  z: ['ź', 'ż', 'ž'],
  ae: ['æ'],
};
const _BR_GLYPHS: Record<string, string[]> = {
  a: ['à', 'á', 'â', 'ã'],
  c: ['ç'],
  e: ['é', 'ê'],
  i: ['í'],
  o: ['ó', 'ô', 'õ'],
  u: ['ú', 'ü'],
  y: ['ý', 'ÿ'],
};
const _EU_GLYPHS: Record<string, string[]> = {
  a: ['á', 'à', 'ă', 'â', 'å', 'ä', 'ã', 'ą', 'ā'],
  c: ['ć', 'ĉ', 'č', 'ċ', 'ç'],
  d: ['ď', 'đ'],
  e: ['é', 'è', 'ĕ', 'ê', 'ě', 'ë', 'ė', 'ę', 'ē'],
  g: ['ğ', 'ĝ', 'ġ', 'ģ'],
  h: ['ĥ', 'ħ'],
  i: ['í', 'ì', 'ĭ', 'î', 'ï', 'ĩ', 'į', 'ī'],
  j: ['ĵ'],
  k: ['ķ', 'ĸ'],
  l: ['ĺ', 'ľ', 'ļ', 'ł'],
  n: ['ń', 'ň', 'ñ', 'ņ'],
  o: ['ó', 'ò', 'ŏ', 'ô', 'ö', 'ő', 'õ', 'ø', 'ō'],
  r: ['ŕ', 'ř', 'ŗ'],
  s: ['ś', 'ŝ', 'š', 'ş'],
  t: ['ť', 'ţ', 'ŧ'],
  u: ['ú', 'ù', 'ŭ', 'û', 'ů', 'ü', 'ű', 'ũ', 'ų', 'ū'],
  w: ['ŵ'],
  y: ['ý', 'ŷ', 'ÿ'],
  z: ['ź', 'ž', 'ż'],
  ae: ['æ'],
  oe: ['œ'],
};
const _FR_GLYPHS: Record<string, string[]> = {
  a: ['à', 'á', 'â', 'ã', 'ä', 'å'],
  c: ['ç'],
  e: ['è', 'é', 'ê', 'ë'],
  i: ['ì', 'í', 'î', 'ï'],
  n: ['ñ'],
  o: ['ò', 'ó', 'ô', 'õ', 'ö'],
  u: ['ù', 'ú', 'û', 'ü'],
  y: ['ý', 'ÿ'],
  ae: ['æ'],
  oe: ['œ'],
};
const GLYPHS_IDN_BY_TLD: Record<string, Record<string, string[]>> = {
  // No IDN support — empty unicode glyph set; only GLYPHS_ASCII applies
  ad: _NO_IDN,
  cz: _NO_IDN,
  sk: _NO_IDN,
  uk: _NO_IDN,
  'co.uk': _NO_IDN,
  nl: _NO_IDN,
  edu: _NO_IDN,
  us: _NO_IDN,
  jp: _NO_IDN,
  'co.jp': _NO_IDN,
  'ad.jp': _NO_IDN,
  'ne.jp': _NO_IDN,
  cn: _NO_IDN,
  'com.cn': _NO_IDN,
  tw: _NO_IDN,
  'com.tw': _NO_IDN,
  'net.tw': _NO_IDN,
  // Country-specific IDN sets
  info: _INFO_GLYPHS,
  br: _BR_GLYPHS,
  'com.br': _BR_GLYPHS,
  dk: { a: ['ä', 'å'], e: ['é'], o: ['ö', 'ø'], u: ['ü'], ae: ['æ'] },
  eu: _EU_GLYPHS,
  de: _EU_GLYPHS,
  pl: _EU_GLYPHS,
  fi: {
    '3': ['ʒ'],
    a: ['á', 'ä', 'å', 'â'],
    c: ['č'],
    d: ['đ'],
    g: ['ǧ', 'ǥ'],
    k: ['ǩ'],
    n: ['ŋ'],
    o: ['õ', 'ö'],
    s: ['š'],
    t: ['ŧ'],
    z: ['ž'],
  },
  no: {
    a: ['á', 'à', 'ä', 'å'],
    c: ['č', 'ç'],
    e: ['é', 'è', 'ê'],
    i: ['ï'],
    n: ['ŋ', 'ń', 'ñ'],
    o: ['ó', 'ò', 'ô', 'ö', 'ø'],
    s: ['š'],
    t: ['ŧ'],
    u: ['ü'],
    z: ['ž'],
    ae: ['æ'],
  },
  be: _FR_GLYPHS,
  fr: _FR_GLYPHS,
  re: _FR_GLYPHS,
  yt: _FR_GLYPHS,
  pm: _FR_GLYPHS,
  wf: _FR_GLYPHS,
  tf: _FR_GLYPHS,
  ch: _FR_GLYPHS,
  li: _FR_GLYPHS,
  ca: {
    a: ['à', 'â'],
    c: ['ç'],
    e: ['è', 'é', 'ê', 'ë'],
    i: ['î', 'ï'],
    o: ['ô'],
    u: ['ù', 'û', 'ü'],
    y: ['ÿ'],
    ae: ['æ'],
    oe: ['œ'],
  },
};

// Matches Python Fuzzer.glyphs_unicode exactly (more glyphs per char than before)
export const GLYPHS_UNICODE: Record<string, string[]> = {
  '2': ['ƻ'],
  '3': ['ʒ'],
  '5': ['ƽ'],
  a: ['ạ', 'ă', 'ȧ', 'ɑ', 'å', 'ą', 'â', 'ǎ', 'á', 'ə', 'ä', 'ã', 'ā', 'à'],
  b: ['ḃ', 'ḅ', 'ƅ', 'ʙ', 'ḇ', 'ɓ'],
  c: ['č', 'ᴄ', 'ċ', 'ç', 'ć', 'ĉ', 'ƈ'],
  d: ['ď', 'ḍ', 'ḋ', 'ɖ', 'ḏ', 'ɗ', 'ḓ', 'ḑ', 'đ'],
  e: ['ê', 'ẹ', 'ę', 'è', 'ḛ', 'ě', 'ɇ', 'ė', 'ĕ', 'é', 'ë', 'ē', 'ȩ'],
  f: ['ḟ', 'ƒ'],
  g: ['ǧ', 'ġ', 'ǵ', 'ğ', 'ɡ', 'ǥ', 'ĝ', 'ģ', 'ɢ'],
  h: ['ȟ', 'ḫ', 'ḩ', 'ḣ', 'ɦ', 'ḥ', 'ḧ', 'ħ', 'ẖ', 'ⱨ', 'ĥ'],
  i: [
    'ɩ',
    'ǐ',
    'í',
    'ɪ',
    'ỉ',
    'ȋ',
    'ɨ',
    'ï',
    'ī',
    'ĩ',
    'ị',
    'î',
    'ı',
    'ĭ',
    'į',
    'ì',
  ],
  j: ['ǰ', 'ĵ', 'ʝ', 'ɉ'],
  k: ['ĸ', 'ǩ', 'ⱪ', 'ḵ', 'ķ', 'ᴋ', 'ḳ'],
  l: ['ĺ', 'ł', 'ɫ', 'ļ', 'ľ'],
  m: ['ᴍ', 'ṁ', 'ḿ', 'ṃ', 'ɱ'],
  n: ['ņ', 'ǹ', 'ń', 'ň', 'ṅ', 'ṉ', 'ṇ', 'ꞑ', 'ñ', 'ŋ'],
  o: ['ö', 'ó', 'ȯ', 'ỏ', 'ô', 'ᴏ', 'ō', 'ò', 'ŏ', 'ơ', 'ő', 'õ', 'ọ', 'ø'],
  p: ['ṗ', 'ƿ', 'ƥ', 'ṕ'],
  q: ['ʠ'],
  r: ['ʀ', 'ȓ', 'ɍ', 'ɾ', 'ř', 'ṛ', 'ɽ', 'ȑ', 'ṙ', 'ŗ', 'ŕ', 'ɼ', 'ṟ'],
  s: ['ṡ', 'ș', 'ŝ', 'ꜱ', 'ʂ', 'š', 'ś', 'ṣ', 'ş'],
  t: ['ť', 'ƫ', 'ţ', 'ṭ', 'ṫ', 'ț', 'ŧ'],
  u: [
    'ᴜ',
    'ų',
    'ŭ',
    'ū',
    'ű',
    'ǔ',
    'ȕ',
    'ư',
    'ù',
    'ů',
    'ʉ',
    'ú',
    'ȗ',
    'ü',
    'û',
    'ũ',
    'ụ',
  ],
  v: ['ᶌ', 'ṿ', 'ᴠ', 'ⱴ', 'ⱱ', 'ṽ'],
  w: ['ᴡ', 'ẇ', 'ẅ', 'ẃ', 'ẘ', 'ẉ', 'ⱳ', 'ŵ', 'ẁ'],
  x: ['ẋ', 'ẍ'],
  y: ['ŷ', 'ÿ', 'ʏ', 'ẏ', 'ɏ', 'ƴ', 'ȳ', 'ý', 'ỿ', 'ỵ'],
  z: ['ž', 'ƶ', 'ẓ', 'ẕ', 'ⱬ', 'ᴢ', 'ż', 'ź', 'ʐ'],
  ae: ['æ'],
  oe: ['œ'],
};

const LATIN_TO_CYRILLIC: Record<string, string> = {
  a: 'а',
  b: 'ь',
  c: 'с',
  d: 'ԁ',
  e: 'е',
  g: 'ԍ',
  h: 'һ',
  i: 'і',
  j: 'ј',
  k: 'к',
  l: 'ӏ',
  m: 'м',
  o: 'о',
  p: 'р',
  q: 'ԛ',
  s: 'ѕ',
  t: 'т',
  v: 'ѵ',
  w: 'ԝ',
  x: 'х',
  y: 'у',
};

// Keyboard adjacency: every key → all other keys that are "nearby" (simplified all-alphabet approach from Python)
const KEYBOARD: Record<string, string> = {
  '1': 'abcdefghijklmnopqrstuvwxyz023456789',
  '2': 'abcdefghijklmnopqrstuvwxyz013456789',
  '3': 'abcdefghijklmnopqrstuvwxyz012456789',
  '4': 'abcdefghijklmnopqrstuvwxyz012356789',
  '5': 'abcdefghijklmnopqrstuvwxyz012346789',
  '6': 'abcdefghijklmnopqrstuvwxyz012345789',
  '7': 'abcdefghijklmnopqrstuvwxyz012345689',
  '8': 'abcdefghijklmnopqrstuvwxyz012345679',
  '9': 'abcdefghijklmnopqrstuvwxyz012345678',
  '0': 'abcdefghijklmnopqrstuvwxyz123456789',
  q: 'abcdefghijklmnoprstuvwxyz0123456789',
  w: 'abcdefghijklmnopqrstuvxyz0123456789',
  e: 'abcdfghijklmnopqrstuvwxyz0123456789',
  r: 'abcdefghijklmnopqstuvwxyz0123456789',
  t: 'abcdefghijklmnopqrsuvwxyz0123456789',
  y: 'abcdefghijklmnopqrstuvwxz0123456789',
  u: 'abcdefghijklmnopqrstvwxyz0123456789',
  i: 'abcdefghjklmnopqrstuvwxyz0123456789',
  o: 'abcdefghijklmnpqrstuvwxyz0123456789',
  p: 'abcdefghijklmnoqrstuvwxyz0123456789',
  a: 'bcdefghijklmnopqrstuvwxyz0123456789',
  s: 'abcdefghijklmnopqrtuvwxyz0123456789',
  d: 'abcefghijklmnopqrstuvwxyz0123456789',
  f: 'abcdeghijklmnopqrstuvwxyz0123456789',
  g: 'abcdefhijklmnopqrstuvwxyz0123456789',
  h: 'abcdefgijklmnopqrstuvwxyz0123456789',
  j: 'abcdefghiklmnopqrstuvwxyz0123456789',
  k: 'abcdefghijlmnopqrstuvwxyz0123456789',
  l: 'abcdefghijkmnopqrstuvwxyz0123456789',
  z: 'abcdefghijklmnopqrstuvwxy0123456789',
  x: 'abcdefghijklmnopqrstuvwyz0123456789',
  c: 'abdefghijklmnopqrstuvwxyz0123456789',
  v: 'abcdefghijklmnopqrstuwxyz0123456789',
  b: 'acdefghijklmnopqrstuvwxyz0123456789',
  n: 'abcdefghijklmopqrstuvwxyz0123456789',
  m: 'abcdefghijklnopqrstuvwxyz0123456789',
};

// ─── TLD parsing ─────────────────────────────────────────────────────────────

export interface ParsedDomain {
  subdomain: string;
  domain: string;
  tld: string;
}

/**
 * Split a host into `{ subdomain, domain, tld }` using the Mozilla Public Suffix List
 * (via `tldts`), mirroring Python dnstwist's domain_tld() which relies on the `tld`
 * package's parse_tld(). The PSL is required so multi-label suffixes such as `com.bd`,
 * `co.uk`, or `edu.in` are recognised — a hardcoded suffix list silently mis-parses any
 * TLD it doesn't enumerate (e.g. `robi.com.bd` → domain `com`/tld `bd` instead of
 * domain `robi`/tld `com.bd`), which changes the fuzzing base and the permutation count.
 */
export function parseDomain(fqdn: string): ParsedDomain {
  const host = fqdn.toLowerCase().replace(/\.$/, '');
  const parsed = parseTld(host);

  if (parsed.domainWithoutSuffix && parsed.publicSuffix) {
    return {
      subdomain: parsed.subdomain ?? '',
      domain: parsed.domainWithoutSuffix,
      tld: parsed.publicSuffix,
    };
  }

  // Fallback mirrors Python domain_tld()'s rsplit('.', 2) path for hosts the PSL can't
  // resolve (e.g. bare labels, unknown suffixes).
  const parts = host.split('.');
  if (parts.length < 2)
    return { subdomain: '', domain: parts[0] ?? '', tld: '' };
  if (parts.length === 2)
    return { subdomain: '', domain: parts[0], tld: parts[1] };
  return {
    subdomain: parts.slice(0, parts.length - 2).join('.'),
    domain: parts[parts.length - 2],
    tld: parts[parts.length - 1],
  };
}

// ─── Fuzzing algorithms ───────────────────────────────────────────────────────

export interface Permutation {
  fuzzer: string;
  domain: string;
}

function* permuteStrings(arr: string[]): Generator<string[]> {
  if (arr.length <= 1) {
    yield arr;
    return;
  }
  for (let i = 0; i < arr.length; i++) {
    const rest = [...arr.slice(0, i), ...arr.slice(i + 1)];
    for (const p of permuteStrings(rest)) yield [arr[i], ...p];
  }
}

export class DnstwistFuzzer {
  private readonly subdomain: string;
  private readonly domain: string;
  private readonly tld: string;

  constructor(
    fqdn: string,
    private readonly dictionary: string[] = [],
    private readonly tldDictionary: string[] = [],
    private readonly wordlist: string[] = [],
    // TLDs applied cross-product style by _fuzzerwithtld (loaded from tlds.dict, not abused_tlds.dict)
    private readonly fuzzerTlds: string[] = [],
    // Optional: wordninja-style splitter for englishsplit + wordswap techniques
    private readonly wordSplit?: (s: string) => string[],
  ) {
    const parsed = parseDomain(fqdn);
    this.subdomain = parsed.subdomain;
    this.domain = parsed.domain;
    this.tld = parsed.tld;
  }

  private makeFqdn(domainPart: string): string {
    return [this.subdomain, domainPart, this.tld].filter(Boolean).join('.');
  }

  // Python _addition() also generates c+domain+1..5 prefix-digit variants
  addition(): string[] {
    const result = new Set<string>();
    // domain+char and char+domain for full alphanumeric set
    for (const c of 'abcdefghijklmnopqrstuvwxyz0123456789') {
      result.add(this.domain + c);
    }
    for (const c of 'abcdefghijklmnopqrstuvwxyz') {
      result.add(c + this.domain);
      // Python also generates c+domain+1..5
      for (let i = 1; i <= 5; i++) {
        result.add(`${c}${this.domain}${i}`);
      }
    }
    return [...result];
  }

  bitsquatting(): string[] {
    const masks = [1, 2, 4, 8, 16, 32, 64, 128];
    const validChars = new Set('abcdefghijklmnopqrstuvwxyz0123456789-');
    const result = new Set<string>();
    for (let i = 0; i < this.domain.length; i++) {
      for (const mask of masks) {
        const flipped = String.fromCharCode(this.domain.charCodeAt(i) ^ mask);
        if (validChars.has(flipped)) {
          result.add(
            this.domain.slice(0, i) + flipped + this.domain.slice(i + 1),
          );
        }
      }
    }
    return [...result];
  }

  cyrillic(): string[] {
    let cdomain = this.domain;
    for (const [latin, cyr] of Object.entries(LATIN_TO_CYRILLIC)) {
      cdomain = cdomain.replaceAll(latin, cyr);
    }
    // Match Python: return [] if ANY position is unchanged (every char must be substituted)
    for (let i = 0; i < cdomain.length; i++) {
      if (cdomain[i] === this.domain[i]) return [];
    }
    return [cdomain];
  }

  homoglyph(): string[] {
    // Match Python: use TLD-specific glyph table when available, else fall back to glyphs_unicode
    const unicodeGlyphs =
      this.tld in GLYPHS_IDN_BY_TLD
        ? GLYPHS_IDN_BY_TLD[this.tld]
        : GLYPHS_UNICODE;
    const glyphs: Record<string, Set<string>> = {};
    for (const [k, vs] of Object.entries(GLYPHS_ASCII)) {
      glyphs[k] = new Set(vs);
    }
    for (const [k, vs] of Object.entries(unicodeGlyphs)) {
      if (!glyphs[k]) glyphs[k] = new Set();
      for (const v of vs) glyphs[k].add(v);
    }

    const mix = (d: string): Set<string> => {
      const out = new Set<string>();
      for (let i = 0; i < d.length; i++) {
        const c = d[i];
        for (const g of glyphs[c] ?? []) {
          out.add(d.slice(0, i) + g + d.slice(i + 1));
        }
      }
      // Two-char substitutions — use replaceAll to match Python str.replace() (replaces every occurrence)
      for (let i = 0; i < d.length - 1; i++) {
        const win = d.slice(i, i + 2);
        for (const c of new Set([win[0], win[1], win])) {
          for (const g of glyphs[c] ?? []) {
            out.add(d.slice(0, i) + win.replaceAll(c, g) + d.slice(i + 2));
          }
        }
      }
      return out;
    };

    const r1 = mix(this.domain);
    const r2 = new Set<string>();
    for (const r of r1) {
      for (const s of mix(r)) r2.add(s);
    }
    return [...new Set([...r1, ...r2])];
  }

  hyphenation(): string[] {
    const result = new Set<string>();
    // Loop 1: insert hyphen at position i
    for (let i = 1; i < this.domain.length; i++) {
      const h = this.domain.slice(0, i) + '-' + this.domain.slice(i);
      if (!h.includes('--')) result.add(h);
    }
    // Loop 3 (Python): '-'.join(domain[:i]) + '-' + '-'.join(domain[i:])
    // Produces character-joined variant like 'o-n-e-s-e-c-u-r-e-a-s-i-a'
    for (let i = 1; i < this.domain.length; i++) {
      const h =
        this.domain.slice(0, i).split('').join('-') +
        '-' +
        this.domain.slice(i).split('').join('-');
      if (!h.includes('--')) result.add(h);
    }
    return [...result];
  }

  insertion(): string[] {
    const result = new Set<string>();
    for (let i = 0; i < this.domain.length - 1; i++) {
      const c = this.domain[i];
      const neighbors = KEYBOARD[c] ?? '';
      for (const n of neighbors) {
        result.add(this.domain.slice(0, i) + n + this.domain.slice(i));
        result.add(this.domain.slice(0, i + 1) + n + this.domain.slice(i + 1));
      }
    }
    return [...result];
  }

  omission(): string[] {
    return Array.from(
      { length: this.domain.length },
      (_, i) => this.domain.slice(0, i) + this.domain.slice(i + 1),
    );
  }

  plural(): string[] {
    const result: string[] = [];
    for (let i = 2; i < this.domain.length - 2; i++) {
      const suffix = 'sxz'.includes(this.domain[i]) ? 'es' : 's';
      result.push(
        this.domain.slice(0, i + 1) + suffix + this.domain.slice(i + 1),
      );
    }
    return result;
  }

  repetition(): string[] {
    return Array.from(
      { length: this.domain.length },
      (_, i) => this.domain.slice(0, i) + this.domain[i] + this.domain.slice(i),
    );
  }

  replacement(): string[] {
    const result = new Set<string>();
    for (let i = 0; i < this.domain.length; i++) {
      const c = this.domain[i];
      for (const r of KEYBOARD[c] ?? '') {
        result.add(this.domain.slice(0, i) + r + this.domain.slice(i + 1));
      }
    }
    return [...result];
  }

  // Python _subdomain() has two loops; second checks domain[i+1] not domain[i-1]
  subdomainFuzz(): string[] {
    const result = new Set<string>();
    if (this.domain.length > 3) {
      for (let i = 1; i < this.domain.length - 1; i++) {
        if (this.domain[i] !== '-' && this.domain[i - 1] !== '-') {
          result.add(this.domain.slice(0, i) + '.' + this.domain.slice(i));
        }
      }
      for (let i = 1; i < this.domain.length - 1; i++) {
        if (this.domain[i] !== '-' && this.domain[i + 1] !== '-') {
          result.add(this.domain.slice(0, i) + '.' + this.domain.slice(i));
        }
      }
    }
    return [...result];
  }

  transposition(): string[] {
    return Array.from(
      { length: this.domain.length - 1 },
      (_, i) =>
        this.domain.slice(0, i) +
        this.domain[i + 1] +
        this.domain[i] +
        this.domain.slice(i + 2),
    );
  }

  vowelSwap(): string[] {
    const vowels = 'aeiou';
    const result = new Set<string>();
    for (let i = 0; i < this.domain.length; i++) {
      if (vowels.includes(this.domain[i])) {
        // Match Python _vowel_swap(): do NOT skip the same-vowel case. It yields the
        // unchanged domain (deduped to the original in generate(), but fed as the base
        // `threats` into fuzzerwithtld → `threats.{tld}`, which Python emits and we must too).
        for (const v of vowels) {
          result.add(this.domain.slice(0, i) + v + this.domain.slice(i + 1));
        }
      }
    }
    return [...result];
  }

  dictionaryFuzz(): string[] {
    const result = new Set<string>();
    for (const word of this.dictionary) {
      if (!this.domain.startsWith(word) || !this.domain.endsWith(word)) {
        result.add(this.domain + '-' + word);
        result.add(this.domain + word);
        result.add(word + '-' + this.domain);
        result.add(word + this.domain);
      }
    }
    if (this.domain.includes('-')) {
      const parts = this.domain.split('-');
      for (const word of this.dictionary) {
        result.add(parts.slice(0, -1).join('-') + '-' + word);
        result.add(word + '-' + parts.slice(1).join('-'));
      }
    }
    return [...result];
  }

  // Python _wordaddition() generates 6 variants per word: bare, dot, hyphen in both orders
  wordAddition(): string[] {
    const result: string[] = [];
    for (const word of this.wordlist) {
      if (!word) continue;
      result.push(
        this.domain + word,
        word + this.domain,
        word + '.' + this.domain,
        this.domain + '.' + word,
        word + '-' + this.domain,
        this.domain + '-' + word,
      );
    }
    return result;
  }

  // Python _englishsplit(): wordninja.split(domain) → each word becomes a permutation
  englishSplit(): string[] {
    if (!this.wordSplit) return [];
    return this.wordSplit(this.domain);
  }

  // Python _wordswap(): all permutations of the wordninja-split words, joined
  wordSwap(): string[] {
    if (!this.wordSplit) return [];
    const words = this.wordSplit(this.domain);
    if (words.length < 2) return [];
    return [...permuteStrings(words)].map((p) => p.join(''));
  }

  // Match Python run(): re_tld = re.compile(r'^[a-z0-9-]{2,63}(?:\.[a-z0-9-]{2,63})?$')
  // Each label of a compound TLD must be 2-63 chars. Single-char labels like "i.ph" are rejected.
  private static readonly VALID_TLD_RE =
    /^[a-z0-9-]{2,63}(?:\.[a-z0-9-]{2,63})?$/;

  tldSwap(): Permutation[] {
    return this.tldDictionary
      .filter((t) => t !== this.tld && DnstwistFuzzer.VALID_TLD_RE.test(t))
      .map((t) => ({
        fuzzer: 'tld-swap',
        domain: [this.subdomain, this.domain, t].filter(Boolean).join('.'),
      }));
  }

  various(): Permutation[] {
    const result: Permutation[] = [];
    const d = this.domain;
    const t = this.tld;
    const s = this.subdomain;

    if (t.includes('.')) {
      const shortTld = t.split('.').pop()!;
      result.push({
        fuzzer: 'various',
        domain: [s, d, shortTld].filter(Boolean).join('.'),
      });
      result.push({
        fuzzer: 'various',
        domain: [s, d + t].filter(Boolean).join('.'),
      });
    } else {
      result.push({
        fuzzer: 'various',
        domain: [s, d + t, t].filter(Boolean).join('.'),
      });
      if (t !== 'com') {
        result.push({
          fuzzer: 'various',
          domain: [s, d + '-' + t, 'com'].filter(Boolean).join('.'),
        });
        result.push({
          fuzzer: 'various',
          domain: [s, d + t, 'com'].filter(Boolean).join('.'),
        });
      }
    }

    // Match Python: additional variants when subdomain exists
    if (s) {
      result.push({ fuzzer: 'various', domain: [s + d, t].join('.') });
      result.push({
        fuzzer: 'various',
        domain: [s.replaceAll('.', '') + d, t].join('.'),
      });
      result.push({ fuzzer: 'various', domain: [s + '-' + d, t].join('.') });
      result.push({
        fuzzer: 'various',
        domain: [s.replaceAll('.', '-') + '-' + d, t].join('.'),
      });
    }

    return result;
  }

  /**
   * Python _fuzzerwithtld(): applies each TLD from tlds.dict (the small regional list, NOT
   * abused_tlds.dict) to every variant produced by 11 core techniques.
   * This cross-product is the single biggest source of the Python/TS count gap.
   */
  fuzzerwithtld(): Permutation[] {
    if (this.fuzzerTlds.length === 0) return [];

    const techniques: Array<() => string[]> = [
      () => this.addition(),
      () => this.bitsquatting(),
      () => this.cyrillic(),
      () => this.hyphenation(),
      () => this.insertion(),
      () => this.omission(),
      () => this.plural(),
      () => this.repetition(),
      () => this.replacement(),
      () => this.transposition(),
      () => this.vowelSwap(),
    ];

    const result: Permutation[] = [];
    const seen = new Set<string>();

    for (const technique of techniques) {
      for (const domainPart of technique()) {
        // Match Python rsplit('.', 1)[0]: strip the last label if there's a dot
        const base = domainPart.includes('.')
          ? domainPart.substring(0, domainPart.lastIndexOf('.'))
          : domainPart;
        for (const tld of this.fuzzerTlds) {
          if (tld.toLowerCase() === 'com') continue;
          // Match Python _fuzzerwithtld(): emit `{base}.{tld}` only — it does NOT prepend
          // the subdomain (unlike the core fuzzers in generate()). Prepending it produced
          // `webyith.0threats.my` instead of `0threats.my`, diverging from the Python output.
          const fqdn = `${base}.${tld}`;
          if (!seen.has(fqdn)) {
            seen.add(fqdn);
            result.push({ fuzzer: 'fuzzerwithtld', domain: fqdn });
          }
        }
      }
    }
    return result;
  }

  /** Generate all permutations with their fuzzer labels */
  generate(): Permutation[] {
    const add = (fuzzer: string, domains: string[]): Permutation[] =>
      domains.map((d) => ({ fuzzer, domain: this.makeFqdn(d) }));

    const perms: Permutation[] = [
      ...add('addition', this.addition()),
      ...add('bitsquatting', this.bitsquatting()),
      ...add('cyrillic', this.cyrillic()),
      ...add('homoglyph', this.homoglyph()),
      ...add('hyphenation', this.hyphenation()),
      ...add('insertion', this.insertion()),
      ...add('omission', this.omission()),
      ...add('plural', this.plural()),
      ...add('repetition', this.repetition()),
      ...add('replacement', this.replacement()),
      ...add('subdomain', this.subdomainFuzz()),
      ...add('transposition', this.transposition()),
      ...add('vowel_swap', this.vowelSwap()),
      ...add('dictionary', this.dictionaryFuzz()),
      ...add('wordaddition', this.wordAddition()),
      ...add('englishsplit', this.englishSplit()),
      ...add('wordswap', this.wordSwap()),
      ...this.tldSwap(),
      ...this.various(),
      ...this.fuzzerwithtld(),
    ];

    // Match Python: always include the original domain as the baseline record (*original).
    // Seed the dedup map so it's always the first entry in the output.
    const originalFqdn = this.makeFqdn(this.domain);
    const seen = new Map<string, Permutation>();
    seen.set(originalFqdn, { fuzzer: '*original', domain: originalFqdn });

    for (const p of perms) {
      if (!p.domain) continue;
      if (!seen.has(p.domain)) seen.set(p.domain, p);
    }

    // Match Python Fuzzer.generate() _punycode() + VALID_FQDN_REGEX filter:
    // convert Unicode homoglyphs to ACE punycode (xn--...) and drop any domain
    // that cannot be encoded (invalid IDN label length, disallowed chars, etc.).
    const result: Permutation[] = [];
    for (const p of seen.values()) {
      if (p.fuzzer === '*original') {
        result.push(p);
        continue;
      }
      try {
        const ace = domainToASCII(p.domain);
        if (ace) result.push({ ...p, domain: ace });
      } catch {
        // invalid IDN — Python also silently drops these
      }
    }
    return result;
  }
}
