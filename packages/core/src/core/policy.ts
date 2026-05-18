/**
 * Policy engine for security rule evaluation
 * @module core/policy
 */

/**
 * Policy action to take when rule matches
 */
export enum PolicyAction {
  /** Allow the request */
  ALLOW = 'allow',
  /** Deny the request */
  DENY = 'deny',
  /** Allow but log the request */
  ALLOW_AND_LOG = 'allow_and_log',
  /** Deny and log the request */
  DENY_AND_LOG = 'deny_and_log',
  /** Rate limit the request */
  RATE_LIMIT = 'rate_limit',
  /** Require additional authentication */
  REQUIRE_MFA = 'require_mfa',
  /** Quarantine the request for review */
  QUARANTINE = 'quarantine',
}

/**
 * Policy rule definition
 */
export interface PolicyRule {
  /** Unique rule identifier */
  id: string;
  /** Human-readable rule name */
  name: string;
  /** Rule description */
  description: string;
  /** Rule condition function */
  condition: (context: PolicyContext) => boolean;
  /** Action to take when condition matches */
  action: PolicyAction;
  /** Rule priority (lower = higher priority) */
  priority: number;
  /** Whether the rule is enabled */
  enabled: boolean;
  /** Rule tags for categorization */
  tags: string[];
  /** Rule metadata */
  metadata: Record<string, unknown>;
}

/**
 * Policy evaluation context
 */
export interface PolicyContext {
  /** User identifier */
  userId?: string;
  /** User roles */
  roles?: string[];
  /** Request resource */
  resource?: string;
  /** Request action */
  action?: string;
  /** Request source IP */
  sourceIP?: string;
  /** Request timestamp */
  timestamp?: Date;
  /** Request headers */
  headers?: Record<string, string>;
  /** Additional context data */
  [key: string]: unknown;
}

/**
 * Policy evaluation result
 */
export interface PolicyEvaluation {
  /** Whether the request is allowed */
  allowed: boolean;
  /** Action taken */
  action: PolicyAction;
  /** Rules that matched */
  matchedRules: string[];
  /** Rules that were evaluated */
  evaluatedRules: string[];
  /** Evaluation timestamp */
  timestamp: Date;
  /** Evaluation reason */
  reason?: string;
  /** Additional metadata */
  metadata: Record<string, unknown>;
}

/**
 * PolicyEngine for evaluating security rules
 */
export class PolicyEngine {
  /** Registered policy rules */
  private rules: Map<string, PolicyRule>;

  /**
   * Create a new PolicyEngine
   */
  constructor() {
    this.rules = new Map();
  }

  /**
   * Add a policy rule
   * @param rule - Policy rule to add
   * @example
   * ```typescript
   * engine.addRule({
   *   id: 'require-mfa-admin',
   *   name: 'Require MFA for admin',
   *   description: 'Admin actions require MFA',
   *   condition: (ctx) => ctx.roles?.includes('admin') && !ctx.mfaVerified,
   *   action: PolicyAction.REQUIRE_MFA,
   *   priority: 10,
   *   enabled: true,
   *   tags: ['auth', 'mfa'],
   *   metadata: {},
   * });
   * ```
   */
  addRule(rule: PolicyRule): void {
    this.rules.set(rule.id, rule);
  }

  /**
   * Remove a policy rule by ID
   * @param ruleId - Rule ID to remove
   * @returns True if rule was removed
   * @example
   * ```typescript
   * engine.removeRule('require-mfa-admin');
   * ```
   */
  removeRule(ruleId: string): boolean {
    return this.rules.delete(ruleId);
  }

  /**
   * Evaluate a single rule against context
   * @param ruleId - Rule ID to evaluate
   * @param context - Evaluation context
   * @returns Evaluation result
   * @example
   * ```typescript
   * const result = engine.evaluate('require-mfa-admin', context);
   * if (!result.allowed) {
   *   throw new Error('Policy violation');
   * }
   * ```
   */
  evaluate(ruleId: string, context: PolicyContext): PolicyEvaluation {
    const rule = this.rules.get(ruleId);
    if (!rule) {
      return {
        allowed: true,
        action: PolicyAction.ALLOW,
        matchedRules: [],
        evaluatedRules: [],
        timestamp: new Date(),
        reason: `Rule ${ruleId} not found`,
        metadata: {},
      };
    }

    if (!rule.enabled) {
      return {
        allowed: true,
        action: PolicyAction.ALLOW,
        matchedRules: [],
        evaluatedRules: [ruleId],
        timestamp: new Date(),
        reason: `Rule ${ruleId} is disabled`,
        metadata: {},
      };
    }

    const matched = rule.condition(context);
    return {
      allowed: matched ? rule.action !== PolicyAction.DENY && rule.action !== PolicyAction.DENY_AND_LOG : true,
      action: matched ? rule.action : PolicyAction.ALLOW,
      matchedRules: matched ? [ruleId] : [],
      evaluatedRules: [ruleId],
      timestamp: new Date(),
      reason: matched ? `Rule ${ruleId} matched` : `Rule ${ruleId} did not match`,
      metadata: { ...rule.metadata },
    };
  }

  /**
   * Evaluate all enabled rules against context
   * Rules are evaluated in priority order (lower priority number = higher priority)
   * @param context - Evaluation context
   * @returns Combined evaluation result
   * @example
   * ```typescript
   * const result = engine.evaluateAll(context);
   * if (!result.allowed) {
   *   console.log('Denied by rules:', result.matchedRules);
   * }
   * ```
   */
  evaluateAll(context: PolicyContext): PolicyEvaluation {
    const enabledRules = Array.from(this.rules.values())
      .filter((r) => r.enabled)
      .sort((a, b) => a.priority - b.priority);

    const matchedRules: string[] = [];
    const evaluatedRules: string[] = [];
    let finalAction = PolicyAction.ALLOW;
    let denyReason: string | undefined;

    for (const rule of enabledRules) {
      evaluatedRules.push(rule.id);
      try {
        if (rule.condition(context)) {
          matchedRules.push(rule.id);
          if (rule.action === PolicyAction.DENY || rule.action === PolicyAction.DENY_AND_LOG) {
            finalAction = rule.action;
            denyReason = `Denied by rule: ${rule.name}`;
            break;
          }
          if (rule.action === PolicyAction.REQUIRE_MFA || rule.action === PolicyAction.QUARANTINE) {
            finalAction = rule.action;
          }
        }
      } catch (error) {
        evaluatedRules.push(`${rule.id} (error)`);
      }
    }

    return {
      allowed: finalAction !== PolicyAction.DENY && finalAction !== PolicyAction.DENY_AND_LOG,
      action: finalAction,
      matchedRules,
      evaluatedRules,
      timestamp: new Date(),
      reason: denyReason,
      metadata: { totalRules: enabledRules.length },
    };
  }

  /**
   * Get all registered rules
   * @param enabledOnly - Whether to return only enabled rules
   * @returns Array of policy rules
   * @example
   * ```typescript
   * const rules = engine.getRules();
   * console.log(`Total rules: ${rules.length}`);
   * ```
   */
  getRules(enabledOnly: boolean = false): PolicyRule[] {
    const rules = Array.from(this.rules.values());
    return enabledOnly ? rules.filter((r) => r.enabled) : rules;
  }

  /**
   * Get a rule by ID
   * @param ruleId - Rule ID
   * @returns Rule or undefined
   */
  getRule(ruleId: string): PolicyRule | undefined {
    return this.rules.get(ruleId);
  }

  /**
   * Get the number of registered rules
   * @returns Rule count
   */
  getRuleCount(): number {
    return this.rules.size;
  }

  /**
   * Enable a rule by ID
   * @param ruleId - Rule ID
   * @returns True if rule was enabled
   */
  enableRule(ruleId: string): boolean {
    const rule = this.rules.get(ruleId);
    if (rule) {
      rule.enabled = true;
      return true;
    }
    return false;
  }

  /**
   * Disable a rule by ID
   * @param ruleId - Rule ID
   * @returns True if rule was disabled
   */
  disableRule(ruleId: string): boolean {
    const rule = this.rules.get(ruleId);
    if (rule) {
      rule.enabled = false;
      return true;
    }
    return false;
  }
}

let _policyEngine: PolicyEngine | null = null;

/**
 * Get the global policy engine singleton
 * @returns PolicyEngine instance
 * @example
 * ```typescript
   const engine = getPolicyEngine();
   * engine.addRule(myRule);
   * ```
   */
export function getPolicyEngine(): PolicyEngine {
  if (!_policyEngine) {
    _policyEngine = new PolicyEngine();
  }
  return _policyEngine;
}
