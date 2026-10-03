import type {
  RuleConditionResolution,
  RuleConfigRecord,
  RuleEvaluationInput,
  RuleEvaluationResult,
  RulePointTier,
} from './rule.types.js';

/**
 * Template method (ported from Reporting): a rule only decides which `points` tier condition
 * applies; the enabled check, tier lookup and `default` fallback live here once.
 */
export abstract class BaseRule {
  abstract readonly key: string;

  protected abstract resolveCondition(
    input: RuleEvaluationInput,
    config: RuleConfigRecord,
  ): RuleConditionResolution | null | Promise<RuleConditionResolution | null>;

  async evaluate(
    config: RuleConfigRecord,
    input: RuleEvaluationInput,
  ): Promise<RuleEvaluationResult> {
    if (!config.enabled) {
      return {
        key: this.key,
        matched: false,
        condition: 'default',
        value: 'rule disabled',
        points: 0,
      };
    }
    const resolved = await this.resolveCondition(input, config);
    if (resolved === null)
      return {
        key: this.key,
        matched: false,
        condition: null,
        value: null,
        points: 0,
      };

    const tier = findTier(config.points, resolved.condition);
    const points = tier?.points ?? 0;
    return {
      key: this.key,
      matched: points > 0,
      condition: tier?.condition ?? resolved.condition,
      value: resolved.value,
      points,
    };
  }
}

function findTier(
  tiers: RulePointTier[],
  condition: string,
): RulePointTier | undefined {
  return (
    tiers.find((t) => t.condition === condition) ??
    tiers.find((t) => t.condition === 'default')
  );
}
