/**
 * Warden Data Classifier
 * Detect PII, secrets, credentials, and other sensitive data.
 */

import { readFile } from 'node:fs/promises';

/**
 * Sensitive data patterns with categories and severity.
 */
const SENSITIVE_PATTERNS = [
  // API Keys & Tokens
  {
    name: 'AWS Access Key',
    category: 'credential',
    severity: 'critical',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
  },
  {
    name: 'AWS Secret Key',
    category: 'credential',
    severity: 'critical',
    regex: /(?:aws_secret_access_key|secret_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
  },
  {
    name: 'Generic API Key',
    category: 'credential',
    severity: 'high',
    regex: /(?:api[_-]?key|apikey)\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?/gi,
  },
  {
    name: 'Bearer Token',
    category: 'credential',
    severity: 'high',
    regex: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g,
  },
  {
    name: 'Private Key',
    category: 'credential',
    severity: 'critical',
    regex: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE\sKEY-----/g,
  },
  {
    name: 'GitHub Token',
    category: 'credential',
    severity: 'critical',
    regex: /\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b/g,
  },

  // Passwords
  {
    name: 'Password Assignment',
    category: 'credential',
    severity: 'critical',
    regex: /(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\s]{8,})["']/gi,
  },

  // PII
  {
    name: 'SSN',
    category: 'pii',
    severity: 'critical',
    regex: /\b(\d{3}-\d{2}-\d{4})\b/g,
  },
  {
    name: 'Email Address',
    category: 'pii',
    severity: 'medium',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
  {
    name: 'Credit Card',
    category: 'pii',
    severity: 'critical',
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
  },
  {
    name: 'Phone Number (US)',
    category: 'pii',
    severity: 'medium',
    regex: /\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b/g,
  },
  {
    name: 'IP Address',
    category: 'infrastructure',
    severity: 'low',
    regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  },

  // Connection Strings
  {
    name: 'Database Connection String',
    category: 'credential',
    severity: 'critical',
    regex: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s"']+:[^\s"']+@[^\s"']+/gi,
  },
];

/**
 * File path patterns that indicate sensitive content.
 */
const SENSITIVE_PATH_PATTERNS = [
  { pattern: /\.env($|\.)/, category: 'credential', severity: 'high', name: 'Environment file' },
  { pattern: /\.pem$/, category: 'credential', severity: 'critical', name: 'PEM certificate' },
  { pattern: /\.key$/, category: 'credential', severity: 'critical', name: 'Key file' },
  { pattern: /id_rsa/, category: 'credential', severity: 'critical', name: 'SSH private key' },
  { pattern: /\.secret/, category: 'credential', severity: 'high', name: 'Secret file' },
  { pattern: /credential/, category: 'credential', severity: 'high', name: 'Credential file' },
  { pattern: /\.htpasswd/, category: 'credential', severity: 'critical', name: 'Apache password file' },
  { pattern: /shadow$/, category: 'credential', severity: 'critical', name: 'Shadow password file' },
  { pattern: /\.pgpass/, category: 'credential', severity: 'critical', name: 'PostgreSQL password file' },
  { pattern: /\.npmrc/, category: 'credential', severity: 'high', name: 'NPM config (may contain tokens)' },
  { pattern: /\.pypirc/, category: 'credential', severity: 'high', name: 'PyPI config (may contain tokens)' },
];

/**
 * Classify content for sensitive data.
 *
 * @param {string} text — content to scan
 * @returns {{ findings: Array<object>, hasSensitiveData: boolean, summary: object }}
 */
export function classifyContent(text) {
  try {
    // Input sanitization
    if (text === null || text === undefined) {
      return { findings: [], hasSensitiveData: false, summary: {} };
    }

    if (typeof text !== 'string') {
      text = String(text);
    }

    if (!text || text.length === 0) {
      return { findings: [], hasSensitiveData: false, summary: {} };
    }

    const findings = [];

    for (const pattern of SENSITIVE_PATTERNS) {
      try {
        // Create fresh regex instance to avoid shared state issues with g flag
        const re = new RegExp(pattern.regex.source, pattern.regex.flags);
        const matches = text.match(re);
        if (matches && matches.length > 0) {
          findings.push({
            name: pattern.name,
            category: pattern.category,
            severity: pattern.severity,
            count: matches.length,
            samples: matches.slice(0, 3).map(m => maskSensitive(m)),
          });
        }
      } catch (err) {
        console.warn(`[Warden] Failed to match pattern ${pattern.name}: ${err.message}`);
        continue;
      }
    }

    const summary = {};
    for (const f of findings) {
      summary[f.category] = (summary[f.category] || 0) + f.count;
    }

    return {
      findings,
      hasSensitiveData: findings.length > 0,
      summary,
    };
  } catch (err) {
    console.error(`[Warden] Error classifying content: ${err.message}`);
    return { findings: [], hasSensitiveData: false, summary: {} };
  }
}

/**
 * Classify a file based on its path patterns and content.
 *
 * @param {string} filePath — file path to classify
 * @returns {Promise<object>}
 */
export async function classifyFile(filePath) {
  try {
    // Input sanitization
    if (!filePath || typeof filePath !== 'string') {
      throw new Error('Invalid file path');
    }

    const result = {
      path: filePath,
      pathFindings: [],
      contentFindings: [],
      overallSeverity: 'none',
      hasSensitiveData: false,
    };

    // Check path patterns
    for (const sp of SENSITIVE_PATH_PATTERNS) {
      try {
        if (sp.pattern.test(filePath)) {
          result.pathFindings.push({
            name: sp.name,
            category: sp.category,
            severity: sp.severity,
          });
        }
      } catch (err) {
        console.warn(`[Warden] Error testing path pattern: ${err.message}`);
        continue;
      }
    }

    // Try to read and scan content
    try {
      const content = await readFile(filePath, 'utf-8');
      const classified = classifyContent(content);
      result.contentFindings = classified.findings;
    } catch {
      // File may not exist or not be readable — that's fine
    }

    const allFindings = [...result.pathFindings, ...result.contentFindings];
    result.hasSensitiveData = allFindings.length > 0;

    const severityRank = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
    result.overallSeverity = allFindings.reduce((max, f) => {
      return severityRank[f.severity] > severityRank[max] ? f.severity : max;
    }, 'none');

    return result;
  } catch (err) {
    console.error(`[Warden] Error classifying file: ${err.message}`);
    throw err;
  }
}

/**
 * Get all sensitive data patterns (for documentation or external use).
 *
 * @returns {Array<{ name: string, category: string, severity: string, regex: string }>}
 */
export function getSensitivePatterns() {
  try {
    return SENSITIVE_PATTERNS.map(p => ({
      name: p.name,
      category: p.category,
      severity: p.severity,
      regex: p.regex.source,
    }));
  } catch (err) {
    console.error(`[Warden] Error getting sensitive patterns: ${err.message}`);
    return [];
  }
}

/**
 * Get all sensitive path patterns.
 *
 * @returns {Array<object>}
 */
export function getSensitivePathPatterns() {
  try {
    return SENSITIVE_PATH_PATTERNS.map(p => ({
      name: p.name,
      category: p.category,
      severity: p.severity,
      pattern: p.pattern.source,
    }));
  } catch (err) {
    console.error(`[Warden] Error getting sensitive path patterns: ${err.message}`);
    return [];
  }
}

/**
 * Mask sensitive data for safe logging.
 */
function maskSensitive(value) {
  if (!value || value.length < 8) return '***';
  return value.slice(0, 4) + '***' + value.slice(-2);
}

/**
 * Custom classification rules registry.
 */
const customPatterns = [];

/**
 * Add a custom classification rule.
 *
 * @param {object} rule — Custom rule configuration
 * @param {string} rule.name — Rule name
 * @param {RegExp|string} rule.regex — Pattern to match (RegExp or regex string)
 * @param {string} rule.category — Category: "credential", "pii", "infrastructure", etc.
 * @param {string} rule.severity — Severity: "critical", "high", "medium", "low"
 * @param {string} [rule.description] — Optional description
 *
 * @example
 * addCustomRule({
 *   name: 'Internal Employee ID',
 *   regex: /EMP-\d{6}/g,
 *   category: 'pii',
 *   severity: 'medium',
 *   description: 'Company employee identifier'
 * });
 */
export function addCustomRule(rule) {
  try {
    if (!rule || typeof rule !== 'object') {
      throw new Error('Rule must be an object');
    }

    if (!rule.name || typeof rule.name !== 'string') {
      throw new Error('Rule must have a name');
    }

    if (!rule.regex) {
      throw new Error('Rule must have a regex pattern');
    }

    if (!rule.category || typeof rule.category !== 'string') {
      throw new Error('Rule must have a category');
    }

    if (!rule.severity || !['critical', 'high', 'medium', 'low'].includes(rule.severity)) {
      throw new Error('Rule must have a valid severity: critical, high, medium, or low');
    }

    // Convert string regex to RegExp if needed
    let regex;
    if (typeof rule.regex === 'string') {
      try {
        regex = new RegExp(rule.regex, 'g');
      } catch (err) {
        throw new Error(`Invalid regex pattern: ${err.message}`);
      }
    } else if (rule.regex instanceof RegExp) {
      // Ensure global flag
      regex = new RegExp(rule.regex.source, rule.regex.flags.includes('g') ? rule.regex.flags : rule.regex.flags + 'g');
    } else {
      throw new Error('Regex must be a RegExp or string');
    }

    const customRule = {
      name: rule.name,
      category: rule.category,
      severity: rule.severity,
      regex,
      description: rule.description || rule.name,
      custom: true,
      addedAt: new Date().toISOString(),
    };

    customPatterns.push(customRule);

    return customRule;
  } catch (err) {
    console.error(`[Warden] Error adding custom rule: ${err.message}`);
    throw err;
  }
}

/**
 * Remove a custom classification rule by name.
 *
 * @param {string} name — Rule name
 * @returns {boolean} True if removed, false if not found
 */
export function removeCustomRule(name) {
  const index = customPatterns.findIndex(r => r.name === name);
  if (index !== -1) {
    customPatterns.splice(index, 1);
    return true;
  }
  return false;
}

/**
 * Get all custom classification rules.
 *
 * @returns {Array<object>}
 */
export function getCustomRules() {
  return customPatterns.map(r => ({
    name: r.name,
    category: r.category,
    severity: r.severity,
    regex: r.regex.source,
    description: r.description,
    addedAt: r.addedAt,
  }));
}

/**
 * Clear all custom rules.
 */
export function clearCustomRules() {
  customPatterns.length = 0;
}

/**
 * Classify content with both built-in and custom rules.
 *
 * @param {string} text — Content to scan
 * @param {object} [options] — Options
 * @param {boolean} [options.includeCustom=true] — Include custom rules
 * @param {boolean} [options.useML=false] — Use ML-based detection (experimental)
 * @returns {{ findings: Array<object>, hasSensitiveData: boolean, summary: object }}
 */
export function classifyContentExtended(text, options = {}) {
  try {
    const { includeCustom = true, useML = false } = options;

    // Start with basic classification
    const result = classifyContent(text);

    // Add custom patterns
    if (includeCustom && customPatterns.length > 0) {
      for (const pattern of customPatterns) {
        try {
          const re = new RegExp(pattern.regex.source, pattern.regex.flags);
          const matches = text.match(re);
          if (matches && matches.length > 0) {
            result.findings.push({
              name: pattern.name,
              category: pattern.category,
              severity: pattern.severity,
              count: matches.length,
              samples: matches.slice(0, 3).map(m => maskSensitive(m)),
              custom: true,
            });

            // Update summary
            result.summary[pattern.category] = (result.summary[pattern.category] || 0) + matches.length;
            result.hasSensitiveData = true;
          }
        } catch (err) {
          console.warn(`[Warden] Failed to match custom pattern ${pattern.name}: ${err.message}`);
          continue;
        }
      }
    }

    // Apply ML-based detection if requested
    if (useML) {
      const mlFindings = detectWithML(text);
      result.findings.push(...mlFindings);

      for (const finding of mlFindings) {
        result.summary[finding.category] = (result.summary[finding.category] || 0) + finding.count;
        result.hasSensitiveData = true;
      }
    }

    return result;
  } catch (err) {
    console.error(`[Warden] Error in extended classification: ${err.message}`);
    return { findings: [], hasSensitiveData: false, summary: {} };
  }
}

/**
 * ML-based sensitive data detection (stub implementation).
 *
 * This is a placeholder for future ML integration. In a production system,
 * this would integrate with ML models trained to detect:
 * - Names and entities
 * - Addresses
 * - Custom business-specific PII
 * - Contextual sensitive information
 *
 * @param {string} text — Content to analyze
 * @returns {Array<object>} ML-detected findings
 */
function detectWithML(text) {
  try {
    // Stub implementation using heuristics
    // In production, this would call an ML service or local model
    const findings = [];

    // Detect potential names (heuristic: capitalized words in sequence)
    const namePattern = /\b[A-Z][a-z]+\s+[A-Z][a-z]+\b/g;
    const nameMatches = text.match(namePattern);
    if (nameMatches && nameMatches.length > 0) {
      // Filter out common false positives
      const filtered = nameMatches.filter(name =>
        !/(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|January|February|March|April|May|June|July|August|September|October|November|December)/i.test(name)
      );

      if (filtered.length > 0) {
        findings.push({
          name: 'Potential Name (ML)',
          category: 'pii',
          severity: 'low',
          count: filtered.length,
          samples: filtered.slice(0, 3),
          ml: true,
          confidence: 0.65,
        });
      }
    }

    // Detect potential addresses (heuristic: number + street keywords)
    const addressPattern = /\b\d+\s+[A-Z][a-z]+\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b/gi;
    const addressMatches = text.match(addressPattern);
    if (addressMatches && addressMatches.length > 0) {
      findings.push({
        name: 'Potential Address (ML)',
        category: 'pii',
        severity: 'medium',
        count: addressMatches.length,
        samples: addressMatches.slice(0, 3),
        ml: true,
        confidence: 0.7,
      });
    }

    // Detect potential sensitive keywords in context
    const sensitiveContextPattern = /\b(confidential|secret|private|internal|proprietary)\s+\w+/gi;
    const contextMatches = text.match(sensitiveContextPattern);
    if (contextMatches && contextMatches.length > 0) {
      findings.push({
        name: 'Sensitive Context (ML)',
        category: 'confidential',
        severity: 'high',
        count: contextMatches.length,
        samples: contextMatches.slice(0, 3),
        ml: true,
        confidence: 0.8,
      });
    }

    return findings;
  } catch (err) {
    console.error(`[Warden] Error in ML detection: ${err.message}`);
    return [];
  }
}

/**
 * Get ML detection configuration and status.
 *
 * @returns {object} ML configuration info
 */
export function getMLConfig() {
  return {
    available: true,
    type: 'heuristic-stub',
    description: 'ML detection is currently using heuristic-based stub implementation',
    capabilities: [
      'Name detection',
      'Address detection',
      'Sensitive context detection',
    ],
    note: 'For production use, integrate with trained ML models or external ML services',
  };
}
