import { Injectable } from '@nestjs/common';
import { getDomain, getDomainWithoutSuffix } from 'tldts';
import { hashDistance } from '../../screenshots/capture/image.js';
import { BaseRule } from '../base-rule.js';
import {
  type RuleConditionResolution,
  type RuleConfigRecord,
  type RuleEvaluationInput,
  RuleKey,
} from '../rule.types.js';

const num = (v: unknown, fallback: number) =>
  typeof v === 'number' && Number.isFinite(v) ? v : fallback;

/**
 * Screenshot looks like the brand's own site: Hamming distance between the look-alike's and
 * the brand reference's 64-bit dHash. `identical` ≤ params.identicalMaxDistance (6 ≈ 91%),
 * `similar` ≤ params.similarMaxDistance (12 ≈ 81%). Not evaluated until both captures exist.
 */
@Injectable()
export class VisualSimilarityRule extends BaseRule {
  readonly key = RuleKey.VISUAL_SIMILARITY;
  protected resolveCondition(
    input: RuleEvaluationInput,
    config: RuleConfigRecord,
  ): RuleConditionResolution | null {
    const a = input.page?.perceptualHash;
    const b = input.reference?.perceptualHash;
    if (!a || !b) return null;
    const d = hashDistance(a, b);
    const value = `${Math.round((1 - d / 64) * 100)}% similar to the brand site`;
    if (d <= num(config.params.identicalMaxDistance, 6))
      return { condition: 'identical', value };
    if (d <= num(config.params.similarMaxDistance, 12))
      return { condition: 'similar', value };
    return { condition: 'default', value };
  }
}

/**
 * What the page contains (strongest first):
 *   credential_form — a password field on a page naming the brand (classic credential phishing);
 *                     also when the form posts to a third-party host
 *   favicon_clone   — the brand's own favicon (byte-identical)
 *   brand_mentions  — the brand is named on a page that is not the brand
 */
@Injectable()
export class PhishingContentRule extends BaseRule {
  readonly key = RuleKey.PHISHING_CONTENT;
  protected resolveCondition(
    input: RuleEvaluationInput,
  ): RuleConditionResolution | null {
    const page = input.page;
    if (!page) return null;
    const label =
      getDomainWithoutSuffix(input.originalDomain) ?? input.originalDomain;
    const haystack = `${page.title ?? ''} ${page.text}`.toLowerCase();
    const mentions =
      label.length >= 3 && haystack.includes(label.toLowerCase());
    const ownHost = getDomain(input.fuzzerDomain);
    const external = page.formActionHosts.filter(
      (h) => getDomain(h) && getDomain(h) !== ownHost,
    );

    if (page.hasPasswordField && (mentions || external.length))
      return {
        condition: 'credential_form',
        value: `password form${mentions ? ` naming "${label}"` : ''}${external.length ? ` posting to ${external[0]}` : ''}`,
      };
    if (
      page.faviconHash &&
      input.reference?.faviconHash &&
      page.faviconHash === input.reference.faviconHash
    )
      return { condition: 'favicon_clone', value: "uses the brand's favicon" };
    if (mentions)
      return { condition: 'brand_mentions', value: `page names "${label}"` };
    return {
      condition: 'default',
      value: page.hasPasswordField
        ? 'login form, no brand reference'
        : 'no brand content',
    };
  }
}
