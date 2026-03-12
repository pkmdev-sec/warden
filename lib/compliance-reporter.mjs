/**
 * Warden Compliance Reporter
 * Generate SOC2, executive summary, and CSV reports for auditors.
 */

import { queryLog } from './audit-logger.mjs';

/**
 * Generate a SOC2-relevant compliance report.
 *
 * Maps audit data to SOC2 Trust Service Criteria:
 *   CC6 — Logical and Physical Access Controls
 *   CC7 — System Operations
 *   CC8 — Change Management
 *
 * @param {object} period — { startDate, endDate }
 * @returns {Promise<object>}
 */
export async function generateSOC2Report(period) {
  try {
    const entries = await queryLog(period);
    const violations = entries.filter(e => e.violations?.length > 0);

  const accessEvents = entries.filter(e =>
    ['Read', 'Write', 'Edit'].includes(e.tool)
  );
  const commandEvents = entries.filter(e => e.tool === 'Bash');
  const changeEvents = entries.filter(e =>
    ['Write', 'Edit', 'NotebookEdit'].includes(e.tool)
  );

  return {
    reportType: 'SOC2',
    generatedAt: new Date().toISOString(),
    period,
    summary: {
      totalActions: entries.length,
      totalViolations: violations.length,
      complianceRate: entries.length > 0
        ? ((1 - violations.length / entries.length) * 100).toFixed(2) + '%'
        : '100.00%',
    },
    controls: {
      CC6_LogicalAccess: {
        description: 'Logical and Physical Access Controls',
        totalAccessEvents: accessEvents.length,
        blockedAccess: accessEvents.filter(e => e.result === 'blocked').length,
        uniqueUsers: [...new Set(accessEvents.map(e => e.user))],
        findings: violations
          .filter(e => ['Read', 'Write', 'Edit'].includes(e.tool))
          .map(summarizeViolation),
      },
      CC7_SystemOperations: {
        description: 'System Operations',
        totalCommands: commandEvents.length,
        blockedCommands: commandEvents.filter(e => e.result === 'blocked').length,
        highRiskCommands: commandEvents.filter(e =>
          /rm\s|drop\s|delete|truncate|shutdown|kill/i.test(e.command || '')
        ).length,
        findings: violations
          .filter(e => e.tool === 'Bash')
          .map(summarizeViolation),
      },
      CC8_ChangeManagement: {
        description: 'Change Management',
        totalChanges: changeEvents.length,
        uniqueFilesChanged: [...new Set(changeEvents.map(e => e.path).filter(Boolean))].length,
        findings: violations
          .filter(e => ['Write', 'Edit', 'NotebookEdit'].includes(e.tool))
          .map(summarizeViolation),
      },
    },
  };
  } catch (err) {
    console.error(`[Warden] Error generating SOC2 report: ${err.message}`);
    throw err;
  }
}

/**
 * Generate an executive summary report.
 *
 * @param {object} period — { startDate, endDate }
 * @returns {Promise<object>}
 */
export async function generateSummary(period) {
  try {
    const entries = await queryLog(period);
    const violations = entries.filter(e => e.violations?.length > 0);

  const toolCounts = {};
  for (const e of entries) {
    toolCounts[e.tool] = (toolCounts[e.tool] || 0) + 1;
  }
  const topTools = Object.entries(toolCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([tool, count]) => ({ tool, count }));

  const uniqueUsers = [...new Set(entries.map(e => e.user))];

  return {
    reportType: 'ExecutiveSummary',
    generatedAt: new Date().toISOString(),
    period,
    totalActions: entries.length,
    totalViolations: violations.length,
    complianceRate: entries.length > 0
      ? ((1 - violations.length / entries.length) * 100).toFixed(2) + '%'
      : '100.00%',
    activeUsers: uniqueUsers.length,
    topTools,
    riskLevel: violations.length === 0 ? 'low' : violations.length < 5 ? 'medium' : 'high',
    recentViolations: violations.slice(-5).map(summarizeViolation),
  };
  } catch (err) {
    console.error(`[Warden] Error generating summary: ${err.message}`);
    throw err;
  }
}

/**
 * Get high-risk actions that need manual review.
 *
 * @param {object} period — { startDate, endDate }
 * @returns {Promise<Array<object>>}
 */
export async function getHighRiskActions(period) {
  try {
    const entries = await queryLog(period);

    const highRisk = entries.filter(entry => {
      if (entry.violations?.length > 0) return true;
      if (entry.result === 'blocked') return true;
      if (/rm\s+-rf|drop\s+table|delete\s+from|truncate|format|shutdown|kill\s+-9/i.test(entry.command || ''))
        return true;
      if (/\.(env|pem|key|secret|credential)/i.test(entry.path || ''))
        return true;
      return false;
    });

    return highRisk.map(entry => ({
      id: entry.id,
      timestamp: entry.timestamp,
      user: entry.user,
      tool: entry.tool,
      command: entry.command,
      path: entry.path,
      result: entry.result,
      riskReasons: getRiskReasons(entry),
      violations: entry.violations || [],
    }));
  } catch (err) {
    console.error(`[Warden] Error getting high-risk actions: ${err.message}`);
    throw err;
  }
}

/**
 * Export audit data as CSV for external auditors.
 *
 * @param {object} period — { startDate, endDate }
 * @returns {Promise<string>} CSV formatted string
 */
export async function exportCSV(period) {
  try {
    const entries = await queryLog(period);

    const headers = ['id', 'timestamp', 'user', 'tool', 'command', 'path', 'result', 'violations'];
    const rows = entries.map(e => [
      csvEscape(e.id),
      csvEscape(e.timestamp),
      csvEscape(e.user),
      csvEscape(e.tool),
      csvEscape(e.command),
      csvEscape(e.path),
      csvEscape(e.result),
      (e.violations || []).length,
    ]);

    return [
      headers.join(','),
      ...rows.map(r => r.join(',')),
    ].join('\n');
  } catch (err) {
    console.error(`[Warden] Error exporting CSV: ${err.message}`);
    throw err;
  }
}

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  if (typeof value !== 'string') return String(value);
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return '"' + value.replace(/"/g, '""') + '"';
  }
  return value;
}

function summarizeViolation(entry) {
  return {
    timestamp: entry.timestamp,
    user: entry.user,
    tool: entry.tool,
    command: entry.command,
    path: entry.path,
    violations: (entry.violations || []).map(v => v.policy || v),
  };
}

function getRiskReasons(entry) {
  const reasons = [];
  if (entry.violations?.length > 0) reasons.push('policy_violation');
  if (entry.result === 'blocked') reasons.push('blocked_action');
  if (/rm\s+-rf|drop\s+table|delete\s+from|truncate|format|shutdown|kill\s+-9/i.test(entry.command || ''))
    reasons.push('destructive_command');
  if (/\.(env|pem|key|secret|credential)/i.test(entry.path || ''))
    reasons.push('sensitive_file_access');
  return reasons;
}
