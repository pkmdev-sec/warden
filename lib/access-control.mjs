/**
 * Warden Access Control
 * File and command access control with glob/regex pattern matching.
 */

import crypto from 'node:crypto';

const fileRules = [];
const commandRules = [];

/**
 * Convert a glob pattern to a RegExp.
 * Supports: *, **, ?
 */
function globToRegex(glob) {
  try {
    let re = '^';
    let i = 0;
    while (i < glob.length) {
      const ch = glob[i];
      if (ch === '*') {
        if (glob[i + 1] === '*') {
          re += '.*';
          i += 2;
          if (glob[i] === '/') { re += '\\/'; i++; }
          continue;
        }
        re += '[^/]*';
      } else if (ch === '?') {
        re += '[^/]';
      } else if (ch === '[' || ch === ']') {
        // Handle character classes - escape them for now to avoid crashes
        re += '\\' + ch;
      } else if (ch === '{' || ch === '}') {
        // Handle brace expansion - escape them for now to avoid crashes
        re += '\\' + ch;
      } else if (ch === '.') {
        re += '\\.';
      } else if (ch === '/') {
        re += '\\/';
      } else if (/[\\^$+.()|]/.test(ch)) {
        // Escape other special regex characters
        re += '\\' + ch;
      } else {
        re += ch;
      }
      i++;
    }
    re += '$';
    return new RegExp(re);
  } catch (err) {
    console.warn(`[Warden] Error converting glob to regex: ${err.message}`);
    // Fallback to simple string matching
    return new RegExp(glob.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  }
}

/**
 * Add an access rule.
 *
 * @param {"file"|"command"} type — rule type
 * @param {string} pattern — glob pattern (file) or regex string (command)
 * @param {"allow"|"block"} action — allow or block
 * @param {object} [options] — { operations?: string[], description?: string }
 */
export function addRule(type, pattern, action, options = {}) {
  try {
    if (!['file', 'command'].includes(type)) {
      throw new Error(`Invalid rule type: ${type}. Must be "file" or "command".`);
    }
    if (!['allow', 'block'].includes(action)) {
      throw new Error(`Invalid action: ${action}. Must be "allow" or "block".`);
    }

    const rule = {
      id: crypto.randomUUID(),
      type,
      pattern,
      action,
      operations: options.operations || ['read', 'write', 'execute', 'delete'],
      description: options.description || '',
      createdAt: new Date().toISOString(),
    };

    if (type === 'file') {
      rule._regex = globToRegex(pattern);
      fileRules.push(rule);
    } else {
      try {
        rule._regex = new RegExp(pattern, 'i');
      } catch {
        rule._regex = new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      }
      commandRules.push(rule);
    }

    return rule;
  } catch (err) {
    console.error(`[Warden] Error adding rule: ${err.message}`);
    throw err;
  }
}

/**
 * Check if a file path is allowed for a given operation.
 *
 * @param {string} filePath — absolute or relative path
 * @param {string} operation — "read", "write", "execute", "delete"
 * @returns {{ allowed: boolean, matchedRule: object|null, reason: string }}
 */
export function checkFileAccess(filePath, operation = 'read') {
  try {
    if (!filePath) {
      return { allowed: false, matchedRule: null, reason: 'No file path provided' };
    }

    // Check rules in reverse order (last added = highest priority)
    for (let i = fileRules.length - 1; i >= 0; i--) {
      const rule = fileRules[i];
      if (!rule.operations.includes(operation)) continue;
      try {
        if (rule._regex.test(filePath)) {
          return {
            allowed: rule.action === 'allow',
            matchedRule: { id: rule.id, pattern: rule.pattern, action: rule.action },
            reason: rule.action === 'block'
              ? `Blocked by rule: ${rule.description || rule.pattern}`
              : `Allowed by rule: ${rule.description || rule.pattern}`,
          };
        }
      } catch (err) {
        console.warn(`[Warden] Error testing rule ${rule.id}: ${err.message}`);
        continue;
      }
    }

    // Default: allow if no rule matches
    return { allowed: true, matchedRule: null, reason: 'No matching rule — default allow' };
  } catch (err) {
    console.error(`[Warden] Error checking file access: ${err.message}`);
    return { allowed: true, matchedRule: null, reason: 'Error checking access — default allow' };
  }
}

/**
 * Check if a command is allowed.
 *
 * @param {string} command — the command string
 * @returns {{ allowed: boolean, matchedRule: object|null, reason: string }}
 */
export function checkCommandAccess(command) {
  try {
    if (!command) {
      return { allowed: false, matchedRule: null, reason: 'No command provided' };
    }

    for (let i = commandRules.length - 1; i >= 0; i--) {
      const rule = commandRules[i];
      try {
        if (rule._regex.test(command)) {
          return {
            allowed: rule.action === 'allow',
            matchedRule: { id: rule.id, pattern: rule.pattern, action: rule.action },
            reason: rule.action === 'block'
              ? `Blocked by rule: ${rule.description || rule.pattern}`
              : `Allowed by rule: ${rule.description || rule.pattern}`,
          };
        }
      } catch (err) {
        console.warn(`[Warden] Error testing command rule ${rule.id}: ${err.message}`);
        continue;
      }
    }

    return { allowed: true, matchedRule: null, reason: 'No matching rule — default allow' };
  } catch (err) {
    console.error(`[Warden] Error checking command access: ${err.message}`);
    return { allowed: true, matchedRule: null, reason: 'Error checking access — default allow' };
  }
}

/**
 * Get all rules of a given type.
 * @param {"file"|"command"} [type]
 * @returns {Array<object>}
 */
export function getRules(type) {
  if (type === 'file') return fileRules.map(sanitizeRule);
  if (type === 'command') return commandRules.map(sanitizeRule);
  return [...fileRules, ...commandRules].map(sanitizeRule);
}

/**
 * Remove a rule by ID.
 * @param {string} id
 * @returns {boolean}
 */
export function removeRule(id) {
  let idx = fileRules.findIndex(r => r.id === id);
  if (idx !== -1) { fileRules.splice(idx, 1); return true; }
  idx = commandRules.findIndex(r => r.id === id);
  if (idx !== -1) { commandRules.splice(idx, 1); return true; }
  return false;
}

/**
 * Clear all rules. Useful for testing.
 */
export function clearRules() {
  fileRules.length = 0;
  commandRules.length = 0;
}

function sanitizeRule(rule) {
  const { _regex, ...rest } = rule;
  return rest;
}
