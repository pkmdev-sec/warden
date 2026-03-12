/**
 * Warden Access Control
 * File and command access control with glob/regex pattern matching.
 */

import crypto from 'node:crypto';

const fileRules = [];
const commandRules = [];

/**
 * Convert a glob pattern to a RegExp.
 * Supports: *, **, ?, [...], {...}, and negation with !
 *
 * Enhanced features:
 * - ** matches any depth of directories
 * - * matches any characters except /
 * - ? matches single character except /
 * - [abc] matches character classes
 * - {a,b,c} matches alternatives (brace expansion)
 * - ! at start negates the pattern
 *
 * @param {string} glob — Glob pattern
 * @returns {RegExp}
 */
function globToRegex(glob) {
  try {
    if (!glob || typeof glob !== 'string') {
      return /^$/; // Empty pattern matches nothing
    }

    let negated = false;
    if (glob.startsWith('!')) {
      negated = true;
      glob = glob.slice(1);
    }

    let re = '^';
    let i = 0;

    while (i < glob.length) {
      const ch = glob[i];

      if (ch === '*') {
        if (glob[i + 1] === '*') {
          // ** matches everything including /
          re += '.*';
          i += 2;
          // Optional trailing slash after **
          if (glob[i] === '/') {
            re += '\\/';
            i++;
          }
          continue;
        }
        // * matches anything except /
        re += '[^/]*';
      } else if (ch === '?') {
        // ? matches single character except /
        re += '[^/]';
      } else if (ch === '[') {
        // Character class [abc] or [a-z]
        const classEnd = glob.indexOf(']', i);
        if (classEnd === -1) {
          // Malformed, escape the bracket
          re += '\\[';
        } else {
          let charClass = glob.slice(i, classEnd + 1);
          // Handle negation [!abc] or [^abc]
          charClass = charClass.replace(/^\[!/, '[^');
          re += charClass;
          i = classEnd; // Will be incremented at end of loop
        }
      } else if (ch === '{') {
        // Brace expansion {a,b,c}
        const braceEnd = glob.indexOf('}', i);
        if (braceEnd === -1) {
          // Malformed, escape the brace
          re += '\\{';
        } else {
          const braceContent = glob.slice(i + 1, braceEnd);
          // Split by comma and create alternation
          const alternatives = braceContent.split(',').map(alt => {
            // Recursively convert each alternative
            return globToRegex(alt).source.replace(/^\^/, '').replace(/\$$/, '');
          });
          re += '(?:' + alternatives.join('|') + ')';
          i = braceEnd; // Will be incremented at end of loop
        }
      } else if (ch === '}' || ch === ']') {
        // Closing braces/brackets outside context - escape
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
    const regex = new RegExp(re);

    // If negated, wrap in a function that inverts the match
    if (negated) {
      regex._negated = true;
    }

    return regex;
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
 * @param {object} [options] — { operations?: string[], description?: string, useRegex?: boolean }
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
      useRegex: options.useRegex || false,
      createdAt: new Date().toISOString(),
    };

    if (type === 'file') {
      if (options.useRegex) {
        // Use pattern as direct regex
        try {
          rule._regex = new RegExp(pattern);
        } catch {
          rule._regex = new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
        }
      } else {
        // Use glob pattern
        rule._regex = globToRegex(pattern);
      }
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

/**
 * Test a glob pattern against a path.
 * Useful for debugging and testing glob patterns.
 *
 * @param {string} pattern — Glob pattern
 * @param {string} path — Path to test
 * @returns {boolean}
 */
export function testGlobPattern(pattern, path) {
  try {
    const regex = globToRegex(pattern);
    return regex.test(path);
  } catch (err) {
    console.error(`[Warden] Error testing glob pattern: ${err.message}`);
    return false;
  }
}

/**
 * Add multiple rules at once.
 *
 * @param {Array<{ type, pattern, action, options? }>} rules — Array of rule configurations
 * @returns {Array<object>} Array of created rules
 */
export function addRules(rules) {
  try {
    if (!Array.isArray(rules)) {
      throw new Error('Rules must be an array');
    }

    const addedRules = [];
    for (const ruleConfig of rules) {
      try {
        const rule = addRule(
          ruleConfig.type,
          ruleConfig.pattern,
          ruleConfig.action,
          ruleConfig.options || {}
        );
        addedRules.push(rule);
      } catch (err) {
        console.warn(`[Warden] Failed to add rule: ${err.message}`);
      }
    }

    return addedRules;
  } catch (err) {
    console.error(`[Warden] Error adding rules: ${err.message}`);
    throw err;
  }
}
