import { domainToUnicode } from 'node:url';
import { getDomain, getDomainWithoutSuffix, getSubdomain } from 'tldts';
import { GLYPHS_UNICODE } from '../fuzzer/dnstwist-fuzzer.js';

export type CtMatchKind = 'typo' | 'tld-swap' | 'combo' | 'subdomain';

export interface BrandTarget {
  id: string;
  /** Registrable domain, e.g. paypal.com */
  domain: string;
  /** Label without the public suffix, e.g. paypal */
  label: string;
  /** Homoglyph-normalised label */
  skeleton: string;
}

export interface CtMatch {
  originalDomainId: string;
  brand: string;
  /** Registrable domain to track (the part an attacker registered). */
  domain: string;
  /** Certificate name that triggered the match (may be a subdomain). */
  certName: string;
  kind: CtMatchKind;
  distance: number;
}

export interface MatcherOptions {
  /** Brand labels shorter than this are only matched as typos, never as substrings (noise). */
  minKeywordLength: number;
  /** Max edit distance for typo matches on labels ≥ 7 chars (shorter labels allow 1). */
  maxEditDistance: number;
}

/** Unicode glyph → the ASCII letter it imitates (inverse of the fuzzer's homoglyph table). */
const UNICODE_TO_ASCII = new Map<string, string>();
for (const [ascii, glyphs] of Object.entries(GLYPHS_UNICODE))
  for (const g of glyphs)
    if (g.length === 1 && !UNICODE_TO_ASCII.has(g))
      UNICODE_TO_ASCII.set(g, ascii);

// Cyrillic / Greek letters that render like Latin ones (the usual IDN-phishing set), on top of the
// fuzzer's table, which focuses on Latin diacritics.
for (const [glyphs, ascii] of [
  ['аαа', 'a'],
  ['ЬЪ', 'b'],
  ['сϲ', 'c'],
  ['ԁ', 'd'],
  ['еε', 'e'],
  ['ғ', 'f'],
  ['ɡ', 'g'],
  ['һ', 'h'],
  ['іιї', 'i'],
  ['ј', 'j'],
  ['κк', 'k'],
  ['ӏ', 'l'],
  ['м', 'm'],
  ['ոп', 'n'],
  ['оοσ', 'o'],
  ['рρ', 'p'],
  ['ԛ', 'q'],
  ['г', 'r'],
  ['ѕ', 's'],
  ['τт', 't'],
  ['υս', 'u'],
  ['νѵ', 'v'],
  ['ԝѡ', 'w'],
  ['хχ', 'x'],
  ['уγ', 'y'],
  ['ᴢ', 'z'],
] as const)
  for (const g of glyphs) UNICODE_TO_ASCII.set(g, ascii);

/** ASCII confusables (multi-char first). Deliberately small: every entry widens what "equal" means. */
const ASCII_CONFUSABLES: [RegExp, string][] = [
  [/rn/g, 'm'],
  [/vv/g, 'w'],
  [/cl/g, 'd'],
  [/0/g, 'o'],
  [/1/g, 'l'],
  [/[|!]/g, 'l'],
  [/5/g, 's'],
  [/\$/g, 's'],
  [/3/g, 'e'],
  [/4/g, 'a'],
  [/7/g, 't'],
  [/8/g, 'b'],
  [/i/g, 'l'], // i / l / 1 collapse together
];

/** Visual skeleton: unicode homoglyphs → ASCII, then ASCII confusables collapsed, hyphens dropped. */
export function skeleton(label: string): string {
  let s = [...(domainToUnicode(label) || label)]
    .map((c) => UNICODE_TO_ASCII.get(c) ?? c)
    .join('')
    .toLowerCase();
  s = s.normalize('NFKD').replace(/\p{M}/gu, '');
  for (const [re, to] of ASCII_CONFUSABLES) s = s.replace(re, to);
  return s.replace(/-/g, '');
}

/** Damerau–Levenshtein (optimal string alignment), with an early exit above `max`. */
export function editDistance(a: string, b: string, max = Infinity): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const prev2: number[] = Array.from({ length: b.length + 1 }, () => 0);
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1])
        v = Math.min(v, prev2[j - 2] + 1);
      cur[j] = v;
      rowMin = Math.min(rowMin, v);
    }
    if (rowMin > max) return max + 1;
    prev2.splice(0, prev2.length, ...prev);
    prev = cur;
  }
  return prev[b.length];
}

export function brandTarget(id: string, domain: string): BrandTarget | null {
  const registrable = getDomain(domain);
  const label = getDomainWithoutSuffix(domain);
  if (!registrable || !label) return null;
  return { id, domain: registrable, label, skeleton: skeleton(label) };
}

/**
 * Does any name in a certificate imitate a brand? Checked per name (wildcards stripped) against
 * every brand; one match per (brand, registrable domain), the strongest kind winning.
 */
export function matchCertificate(
  names: readonly string[],
  brands: readonly BrandTarget[],
  opts: MatcherOptions,
): CtMatch[] {
  const out = new Map<string, CtMatch>();
  const rank: Record<CtMatchKind, number> = {
    typo: 0,
    'tld-swap': 1,
    combo: 2,
    subdomain: 3,
  };
  for (const raw of names) {
    const name = raw.toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
    const registrable = getDomain(name);
    const label = getDomainWithoutSuffix(name);
    if (!registrable || !label) continue;
    const sub = getSubdomain(name) ?? '';
    const sk = skeleton(label);
    for (const b of brands) {
      if (registrable === b.domain) continue; // the brand's own certificates
      let kind: CtMatchKind | null = null;
      let distance = 0;
      if (label === b.label) kind = 'tld-swap';
      else {
        const max = b.label.length >= 7 ? opts.maxEditDistance : 1;
        distance = Math.min(
          editDistance(label, b.label, max),
          editDistance(sk, b.skeleton, max),
        );
        if (distance <= max) kind = 'typo';
        else if (
          b.label.length >= opts.minKeywordLength &&
          (label.includes(b.label) || sk.includes(b.skeleton))
        ) {
          kind = 'combo';
          distance = 0;
        } else if (
          b.label.length >= opts.minKeywordLength &&
          sub
            .split(/[.-]/)
            .some((part) => part === b.label || skeleton(part) === b.skeleton)
        ) {
          kind = 'subdomain';
          distance = 0;
        }
      }
      if (!kind) continue;
      const key = `${b.id}|${registrable}`;
      const prev = out.get(key);
      if (!prev || rank[kind] < rank[prev.kind])
        out.set(key, {
          originalDomainId: b.id,
          brand: b.domain,
          domain: registrable,
          certName: name,
          kind,
          distance,
        });
    }
  }
  return [...out.values()];
}
