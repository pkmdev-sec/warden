/**
 * Warden Audit Logger
 * Complete audit trail with JSONL backend.
 */

import { appendFile, readFile, mkdir, writeFile, stat } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';

const AUDIT_DIR = join(homedir(), '.warden');
const AUDIT_LOG = join(AUDIT_DIR, 'audit.jsonl');

/**
 * Ensure the audit directory and log file exist.
 */
async function ensureAuditLog() {
  try {
    await stat(AUDIT_DIR);
  } catch {
    await mkdir(AUDIT_DIR, { recursive: true });
  }
  try {
    await stat(AUDIT_LOG);
  } catch {
    await writeFile(AUDIT_LOG, '', 'utf-8');
  }
}

/**
 * Log an action to the audit trail.
 *
 * @param {object} action — { tool, command, path, params, user, result, ... }
 * @returns {Promise<object>} the logged entry
 */
export async function logAction(action) {
  await ensureAuditLog();

  const entry = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    user: action.user || process.env.USER || 'unknown',
    tool: action.tool || 'unknown',
    command: action.command || null,
    path: action.path || null,
    params: action.params || {},
    result: action.result || 'unknown',
    violations: action.violations || [],
    metadata: action.metadata || {},
  };

  await appendFile(AUDIT_LOG, JSON.stringify(entry) + '\n', 'utf-8');
  return entry;
}

/**
 * Read all log entries, optionally applying filters.
 *
 * @param {object} [filters] — { user?, tool?, result?, startDate?, endDate?, path? }
 * @returns {Promise<Array<object>>}
 */
export async function queryLog(filters = {}) {
  await ensureAuditLog();

  const entries = [];
  const stream = createReadStream(AUDIT_LOG, 'utf-8');
  const rl = createInterface({ input: stream, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }

    if (filters.user && entry.user !== filters.user) continue;
    if (filters.tool && entry.tool !== filters.tool) continue;
    if (filters.result && entry.result !== filters.result) continue;
    if (filters.path && !entry.path?.startsWith(filters.path)) continue;

    if (filters.startDate) {
      const start = new Date(filters.startDate);
      if (new Date(entry.timestamp) < start) continue;
    }
    if (filters.endDate) {
      const end = new Date(filters.endDate);
      if (new Date(entry.timestamp) > end) continue;
    }

    entries.push(entry);
  }

  return entries;
}

/**
 * Generate a compliance report for a given period.
 *
 * @param {object} period — { startDate, endDate }
 * @param {string} [format="json"] — "json" or "text"
 * @returns {Promise<object|string>}
 */
export async function generateReport(period, format = 'json') {
  const entries = await queryLog(period);
  const stats = computeStats(entries);
  const violations = entries.filter(e => e.violations && e.violations.length > 0);

  const report = {
    period,
    generatedAt: new Date().toISOString(),
    totalActions: entries.length,
    totalViolations: violations.length,
    stats,
    recentViolations: violations.slice(-20),
  };

  if (format === 'text') {
    return formatTextReport(report);
  }

  return report;
}

/**
 * Get statistics for a given period.
 *
 * @param {object} period — { startDate?, endDate? }
 * @returns {Promise<object>}
 */
export async function getStats(period = {}) {
  const entries = await queryLog(period);
  return computeStats(entries);
}

/**
 * Compute stats from a set of entries.
 */
function computeStats(entries) {
  const toolCounts = {};
  const userCounts = {};
  const resultCounts = {};
  let violationCount = 0;

  for (const entry of entries) {
    toolCounts[entry.tool] = (toolCounts[entry.tool] || 0) + 1;
    userCounts[entry.user] = (userCounts[entry.user] || 0) + 1;
    resultCounts[entry.result] = (resultCounts[entry.result] || 0) + 1;
    if (entry.violations && entry.violations.length > 0) violationCount++;
  }

  const topTools = Object.entries(toolCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([tool, count]) => ({ tool, count }));

  return {
    totalActions: entries.length,
    violationCount,
    topTools,
    userCounts,
    resultCounts,
  };
}

/**
 * Format report as readable text.
 */
function formatTextReport(report) {
  const lines = [
    '═══════════════════════════════════════════════',
    '  WARDEN COMPLIANCE REPORT',
    '═══════════════════════════════════════════════',
    `  Generated: ${report.generatedAt}`,
    `  Period: ${report.period.startDate || 'all'} — ${report.period.endDate || 'now'}`,
    '',
    `  Total Actions:    ${report.totalActions}`,
    `  Total Violations: ${report.totalViolations}`,
    '',
    '  Top Tools:',
  ];

  for (const { tool, count } of report.stats.topTools) {
    lines.push(`    ${tool}: ${count}`);
  }

  if (report.recentViolations.length > 0) {
    lines.push('', '  Recent Violations:');
    for (const v of report.recentViolations) {
      lines.push(`    [${v.timestamp}] ${v.tool} — ${v.violations.map(x => x.policy || x).join(', ')}`);
    }
  }

  lines.push('═══════════════════════════════════════════════');
  return lines.join('\n');
}

/**
 * Get the audit log file path (for testing/external use).
 */
export function getAuditLogPath() {
  return AUDIT_LOG;
}
