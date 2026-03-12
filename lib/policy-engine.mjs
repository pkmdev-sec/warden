/**
 * Warden Policy Engine
 * Parse and enforce enterprise governance policies.
 */

import { readdir, readFile } from 'node:fs/promises';
import { join, extname } from 'node:path';

const loadedPolicies = new Map();

/**
 * Load all policy files from a directory.
 * @param {string} dir — path to directory containing .json policy files
 * @returns {Promise<Map<string, object>>} loaded policies keyed by name
 */
export async function loadPolicies(dir) {
  try {
    loadedPolicies.clear();
    const entries = await readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isFile() || extname(entry.name) !== '.json') continue;
      const filePath = join(dir, entry.name);
      try {
        const raw = await readFile(filePath, 'utf-8');
        const policy = JSON.parse(raw);

        if (!policy.name || !Array.isArray(policy.rules)) {
          console.warn(`[Warden] Skipping invalid policy file ${entry.name}: missing "name" or "rules" array`);
          continue;
        }

        loadedPolicies.set(policy.name, policy);
      } catch (err) {
        console.warn(`[Warden] Failed to load policy ${entry.name}: ${err.message}`);
        continue;
      }
    }

    return loadedPolicies;
  } catch (err) {
    console.error(`[Warden] Failed to load policies from ${dir}: ${err.message}`);
    return loadedPolicies;
  }
}

/**
 * Get all currently loaded policies.
 * @returns {Map<string, object>}
 */
export function getPolicies() {
  return loadedPolicies;
}

/**
 * Check if a single rule matches an action.
 *
 * Rule format:
 *   { match: { tool?, command?, path?, pattern? }, action: "allow"|"block"|"warn" }
 *
 * Matching logic:
 *   - If match.tool is set, action.tool must equal it (case-insensitive)
 *   - If match.command is set, it's treated as a regex against action.command
 *   - If match.path is set, it's treated as a glob-like prefix against action.path
 *   - If match.pattern is set, it's treated as a regex against JSON.stringify(action)
 *   - All specified conditions must match (AND logic)
 *
 * @param {object} rule
 * @param {object} action — { tool, command, path, params, ... }
 * @returns {boolean}
 */
export function matchRule(rule, action) {
  try {
    if (!rule || !rule.match || !action) return false;

  const { match } = rule;

  // An empty match object matches nothing (require at least one condition)
  const conditions = ['tool', 'command', 'path', 'pattern'];
  if (!conditions.some(c => c in match)) return false;

  if (match.tool) {
    if (!action.tool) return false;
    if (action.tool.toLowerCase() !== match.tool.toLowerCase()) return false;
  }

  if (match.command) {
    if (!action.command) return false;
    try {
      const re = new RegExp(match.command, 'i');
      if (!re.test(action.command)) return false;
    } catch {
      if (!action.command.includes(match.command)) return false;
    }
  }

  if (match.path) {
    if (!action.path) return false;
    // Convert glob pattern to regex for proper matching
    // Supports *, **, and simple path patterns
    const globPattern = match.path
      .replace(/\*\*/g, '<!DOUBLESTAR!>')
      .replace(/\*/g, '[^/]*')
      .replace(/<!DOUBLESTAR!>/g, '.*')
      .replace(/\?/g, '[^/]')
      .replace(/\./g, '\\.')
      .replace(/\//g, '\\/');
    try {
      const re = new RegExp(globPattern);
      if (!re.test(action.path)) return false;
    } catch {
      // Fallback to simple substring match if regex fails
      if (!action.path.includes(match.path.replace(/\*/g, ''))) return false;
    }
  }

  if (match.pattern) {
    const serialized = JSON.stringify(action);
    try {
      const re = new RegExp(match.pattern, 'i');
      if (!re.test(serialized)) return false;
    } catch {
      if (!serialized.includes(match.pattern)) return false;
    }
  }

  return true;
  } catch (err) {
    console.warn(`[Warden] Error matching rule: ${err.message}`);
    return false;
  }
}

/**
 * Get all policies and rules violated by an action.
 * A violation occurs when a rule matches and its action is "block" or "warn".
 *
 * @param {object} action
 * @returns {Array<{ policy: string, rule: object, severity: string }>}
 */
export function getViolations(action) {
  try {
    const violations = [];

    for (const [name, policy] of loadedPolicies) {
      if (!policy || !Array.isArray(policy.rules)) continue;
      for (const rule of policy.rules) {
        if (matchRule(rule, action) && (rule.action === 'block' || rule.action === 'warn')) {
          violations.push({
            policy: name,
            rule,
            severity: rule.action === 'block' ? 'critical' : 'warning',
            description: rule.description || policy.description || name,
          });
        }
      }
    }

    return violations;
  } catch (err) {
    console.error(`[Warden] Error getting violations: ${err.message}`);
    return [];
  }
}

/**
 * Evaluate an action against all loaded policies.
 *
 * @param {object} action — { tool, command, path, params, user, ... }
 * @param {object} [context] — optional additional context (e.g., environment, role)
 * @returns {{ allowed: boolean, violations: Array, warnings: Array }}
 */
export function evaluateAction(action, context = {}) {
  try {
    const enrichedAction = { ...action, ...context };
    const violations = getViolations(enrichedAction);

    const blocks = violations.filter(v => v.severity === 'critical');
    const warnings = violations.filter(v => v.severity === 'warning');

    return {
      allowed: blocks.length === 0,
      violations: blocks,
      warnings,
    };
  } catch (err) {
    console.error(`[Warden] Error evaluating action: ${err.message}`);
    return {
      allowed: true,
      violations: [],
      warnings: [],
    };
  }
}

/**
 * Compose multiple policies using AND/OR logic.
 *
 * @param {Array<object>} policies — Array of policy objects
 * @param {"AND"|"OR"} operator — Logical operator to apply
 * @param {object} [metadata] — Optional metadata for the composed policy
 * @returns {object} A new composed policy
 *
 * @example
 * // AND: all policies must pass (strictest)
 * const strictPolicy = composePolicies([policy1, policy2], "AND", { name: "strict-combined" });
 *
 * // OR: at least one policy must pass (most permissive)
 * const permissivePolicy = composePolicies([policy1, policy2], "OR", { name: "permissive-combined" });
 */
export function composePolicies(policies, operator = 'AND', metadata = {}) {
  try {
    if (!Array.isArray(policies) || policies.length === 0) {
      throw new Error('Policies must be a non-empty array');
    }

    if (!['AND', 'OR'].includes(operator)) {
      throw new Error('Operator must be "AND" or "OR"');
    }

    // Validate all policies have required structure
    for (const policy of policies) {
      if (!policy || typeof policy !== 'object') {
        throw new Error('Each policy must be an object');
      }
      if (!policy.name || !Array.isArray(policy.rules)) {
        throw new Error('Each policy must have a name and rules array');
      }
    }

    const composedPolicy = {
      name: metadata.name || `composed-${operator.toLowerCase()}-${Date.now()}`,
      description: metadata.description || `Composed policy using ${operator} logic from ${policies.length} policies`,
      composition: {
        operator,
        policies: policies.map(p => p.name),
      },
      rules: [],
      createdAt: new Date().toISOString(),
    };

    if (operator === 'AND') {
      // AND: combine all rules with "block" taking precedence
      // If any policy blocks, the composed policy blocks
      const allRules = [];
      for (const policy of policies) {
        for (const rule of policy.rules) {
          allRules.push({
            ...rule,
            sourcePolicy: policy.name,
          });
        }
      }
      composedPolicy.rules = allRules;
    } else if (operator === 'OR') {
      // OR: Only block if ALL policies would block the same action
      // Convert to: allow if at least one policy allows
      const blockRules = [];

      // Collect all block rules - an action is only blocked if it matches blocks in ALL policies
      for (const policy of policies) {
        const policyBlockRules = policy.rules.filter(r => r.action === 'block');
        blockRules.push({
          policyName: policy.name,
          rules: policyBlockRules,
        });
      }

      // For OR composition, we need to mark rules with special handling
      // Rules will be evaluated with OR logic in evaluateComposedPolicy
      composedPolicy.rules = policies.flatMap(policy =>
        policy.rules.map(rule => ({
          ...rule,
          sourcePolicy: policy.name,
          compositionOperator: 'OR',
        }))
      );
    }

    return composedPolicy;
  } catch (err) {
    console.error(`[Warden] Error composing policies: ${err.message}`);
    throw err;
  }
}

/**
 * Evaluate an action against a composed policy with proper AND/OR semantics.
 *
 * @param {object} composedPolicy — A policy created with composePolicies()
 * @param {object} action — The action to evaluate
 * @param {object} [context] — Optional context
 * @returns {{ allowed: boolean, violations: Array, warnings: Array }}
 */
export function evaluateComposedPolicy(composedPolicy, action, context = {}) {
  try {
    if (!composedPolicy || !composedPolicy.composition) {
      throw new Error('Invalid composed policy');
    }

    const enrichedAction = { ...action, ...context };
    const operator = composedPolicy.composition.operator;

    if (operator === 'AND') {
      // AND logic: check all rules, block if any blocks
      const violations = [];
      const warnings = [];

      for (const rule of composedPolicy.rules) {
        if (matchRule(rule, enrichedAction)) {
          if (rule.action === 'block') {
            violations.push({
              policy: composedPolicy.name,
              sourcePolicy: rule.sourcePolicy,
              rule,
              severity: 'critical',
              description: rule.description || `Blocked by ${rule.sourcePolicy}`,
            });
          } else if (rule.action === 'warn') {
            warnings.push({
              policy: composedPolicy.name,
              sourcePolicy: rule.sourcePolicy,
              rule,
              severity: 'warning',
              description: rule.description || `Warning from ${rule.sourcePolicy}`,
            });
          }
        }
      }

      return {
        allowed: violations.length === 0,
        violations,
        warnings,
        composition: { operator: 'AND', policiesEvaluated: composedPolicy.composition.policies },
      };
    } else if (operator === 'OR') {
      // OR logic: allow if at least one policy allows
      // Block only if ALL source policies would block
      const policyResults = new Map();

      // Group rules by source policy
      for (const rule of composedPolicy.rules) {
        if (!policyResults.has(rule.sourcePolicy)) {
          policyResults.set(rule.sourcePolicy, { blocks: [], warns: [], hasMatch: false });
        }

        if (matchRule(rule, enrichedAction)) {
          const result = policyResults.get(rule.sourcePolicy);
          result.hasMatch = true;

          if (rule.action === 'block') {
            result.blocks.push(rule);
          } else if (rule.action === 'warn') {
            result.warns.push(rule);
          }
        }
      }

      // Check if ALL policies that matched would block
      const matchedPolicies = Array.from(policyResults.entries()).filter(([_, r]) => r.hasMatch);

      if (matchedPolicies.length === 0) {
        // No policies matched, default allow
        return {
          allowed: true,
          violations: [],
          warnings: [],
          composition: { operator: 'OR', policiesEvaluated: composedPolicy.composition.policies },
        };
      }

      const allWouldBlock = matchedPolicies.every(([_, r]) => r.blocks.length > 0);
      const violations = [];
      const warnings = [];

      if (allWouldBlock) {
        // All policies would block
        for (const [policyName, result] of matchedPolicies) {
          for (const rule of result.blocks) {
            violations.push({
              policy: composedPolicy.name,
              sourcePolicy: policyName,
              rule,
              severity: 'critical',
              description: rule.description || `Blocked by ${policyName}`,
            });
          }
        }
      }

      // Collect warnings from all policies
      for (const [policyName, result] of matchedPolicies) {
        for (const rule of result.warns) {
          warnings.push({
            policy: composedPolicy.name,
            sourcePolicy: policyName,
            rule,
            severity: 'warning',
            description: rule.description || `Warning from ${policyName}`,
          });
        }
      }

      return {
        allowed: !allWouldBlock,
        violations,
        warnings,
        composition: { operator: 'OR', policiesEvaluated: composedPolicy.composition.policies },
      };
    }

    throw new Error(`Unknown operator: ${operator}`);
  } catch (err) {
    console.error(`[Warden] Error evaluating composed policy: ${err.message}`);
    return {
      allowed: true,
      violations: [],
      warnings: [],
    };
  }
}

/**
 * Evaluate an action in dry-run mode — reports what WOULD happen without blocking.
 *
 * @param {object} action — The action to test
 * @param {object} [context={}] — Additional context
 * @returns {object} Dry-run result with would-be violations
 */
export function dryRun(action, context = {}) {
  try {
    const result = evaluateAction(action, context);
    return {
      ...result,
      dryRun: true,
      wouldBlock: !result.allowed,
      wouldWarn: result.warnings?.length > 0,
      summary: !result.allowed
        ? `WOULD BLOCK: ${result.violations?.map(v => v.rule?.message || v.rule?.description || v.description || 'Policy violation').join('; ')}`
        : result.warnings?.length > 0
          ? `WOULD WARN: ${result.warnings?.map(w => w.rule?.message || w.rule?.description || w.description || 'Policy warning').join('; ')}`
          : 'WOULD ALLOW: No policy violations'
    };
  } catch (err) {
    console.error(`[Warden] Error in dry-run: ${err.message}`);
    return {
      dryRun: true,
      wouldBlock: false,
      wouldWarn: false,
      summary: 'ERROR: Dry-run evaluation failed',
      error: err.message,
    };
  }
}

/**
 * Test a policy file against a set of test actions.
 *
 * @param {string} policyPath — Path to policy JSON file
 * @param {object[]} testActions — Array of test actions
 * @returns {Promise<object[]>} Results for each test action
 */
export async function testPolicy(policyPath, testActions) {
  try {
    const { readFile } = await import('node:fs/promises');
    const raw = await readFile(policyPath, 'utf-8');
    const policyData = JSON.parse(raw);

    if (!policyData.name || !Array.isArray(policyData.rules)) {
      throw new Error('Invalid policy file: missing "name" or "rules" array');
    }

    return testActions.map(action => {
      const violations = [];
      const warnings = [];

      for (const rule of policyData.rules) {
        if (matchRule(rule, action)) {
          if (rule.action === 'block') {
            violations.push({
              rule: rule.id || rule.description,
              message: rule.message || rule.description || 'Policy violation',
              severity: 'critical',
            });
          } else if (rule.action === 'warn') {
            warnings.push({
              rule: rule.id || rule.description,
              message: rule.message || rule.description || 'Policy warning',
              severity: 'warning',
            });
          }
        }
      }

      return {
        action,
        policy: policyData.name,
        allowed: violations.length === 0,
        violations,
        warnings,
        dryRun: true,
        summary: violations.length > 0
          ? `WOULD BLOCK: ${violations.map(v => v.message).join('; ')}`
          : warnings.length > 0
            ? `WOULD WARN: ${warnings.map(w => w.message).join('; ')}`
            : 'WOULD ALLOW: No policy violations'
      };
    });
  } catch (err) {
    console.error(`[Warden] Error testing policy: ${err.message}`);
    throw err;
  }
}
