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
  loadedPolicies.clear();
  const entries = await readdir(dir, { withFileTypes: true });

  for (const entry of entries) {
    if (!entry.isFile() || extname(entry.name) !== '.json') continue;
    const filePath = join(dir, entry.name);
    const raw = await readFile(filePath, 'utf-8');
    const policy = JSON.parse(raw);

    if (!policy.name || !Array.isArray(policy.rules)) {
      throw new Error(`Invalid policy file ${entry.name}: missing "name" or "rules" array`);
    }

    loadedPolicies.set(policy.name, policy);
  }

  return loadedPolicies;
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
    const normalized = match.path.replace(/\*/g, '');
    if (!action.path.startsWith(normalized)) return false;
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
}

/**
 * Get all policies and rules violated by an action.
 * A violation occurs when a rule matches and its action is "block" or "warn".
 *
 * @param {object} action
 * @returns {Array<{ policy: string, rule: object, severity: string }>}
 */
export function getViolations(action) {
  const violations = [];

  for (const [name, policy] of loadedPolicies) {
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
}

/**
 * Evaluate an action against all loaded policies.
 *
 * @param {object} action — { tool, command, path, params, user, ... }
 * @param {object} [context] — optional additional context (e.g., environment, role)
 * @returns {{ allowed: boolean, violations: Array, warnings: Array }}
 */
export function evaluateAction(action, context = {}) {
  const enrichedAction = { ...action, ...context };
  const violations = getViolations(enrichedAction);

  const blocks = violations.filter(v => v.severity === 'critical');
  const warnings = violations.filter(v => v.severity === 'warning');

  return {
    allowed: blocks.length === 0,
    violations: blocks,
    warnings,
  };
}
