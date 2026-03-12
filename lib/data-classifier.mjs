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
