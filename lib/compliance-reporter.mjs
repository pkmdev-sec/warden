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

/**
 * Custom report template registry.
 */
const reportTemplates = new Map();

/**
 * Register a custom report template.
 *
 * @param {string} name — Template name
 * @param {object} template — Template configuration
 * @param {string} template.description — Template description
 * @param {Function} template.generator — Function that generates the report: (entries) => object
 * @param {string} [template.format="json"] — Output format: "json", "text", "csv", "html"
 * @param {Function} [template.formatter] — Optional custom formatter: (data) => string
 *
 * @example
 * registerReportTemplate('custom', {
 *   description: 'Custom compliance report',
 *   generator: (entries) => ({ total: entries.length }),
 *   format: 'json'
 * });
 */
export function registerReportTemplate(name, template) {
  try {
    if (!name || typeof name !== 'string') {
      throw new Error('Template name must be a non-empty string');
    }

    if (!template || typeof template !== 'object') {
      throw new Error('Template must be an object');
    }

    if (typeof template.generator !== 'function') {
      throw new Error('Template must have a generator function');
    }

    reportTemplates.set(name, {
      name,
      description: template.description || name,
      generator: template.generator,
      format: template.format || 'json',
      formatter: template.formatter || null,
      registeredAt: new Date().toISOString(),
    });

    return true;
  } catch (err) {
    console.error(`[Warden] Error registering report template: ${err.message}`);
    throw err;
  }
}

/**
 * Generate a report using a custom template.
 *
 * @param {string} templateName — Name of registered template
 * @param {object} period — { startDate?, endDate? }
 * @param {object} [options] — Additional options passed to generator
 * @returns {Promise<object|string>}
 */
export async function generateCustomReport(templateName, period, options = {}) {
  try {
    const template = reportTemplates.get(templateName);

    if (!template) {
      throw new Error(`Template not found: ${templateName}`);
    }

    // Fetch entries for the period
    const entries = await queryLog(period);

    // Generate report data using template generator
    const reportData = await template.generator(entries, options);

    // Apply custom formatter if provided
    if (template.formatter) {
      return template.formatter(reportData);
    }

    // Apply default formatting based on format type
    if (template.format === 'text') {
      return formatAsText(reportData);
    } else if (template.format === 'csv') {
      return formatAsCSV(reportData);
    } else if (template.format === 'html') {
      return formatAsHTML(reportData);
    }

    // Default: return as JSON
    return reportData;
  } catch (err) {
    console.error(`[Warden] Error generating custom report: ${err.message}`);
    throw err;
  }
}

/**
 * Get all registered report templates.
 *
 * @returns {Array<{ name: string, description: string, format: string }>}
 */
export function getReportTemplates() {
  return Array.from(reportTemplates.values()).map(t => ({
    name: t.name,
    description: t.description,
    format: t.format,
    registeredAt: t.registeredAt,
  }));
}

/**
 * Unregister a report template.
 *
 * @param {string} name — Template name
 * @returns {boolean}
 */
export function unregisterReportTemplate(name) {
  return reportTemplates.delete(name);
}

/**
 * Format report data as plain text.
 */
function formatAsText(data) {
  try {
    if (typeof data === 'string') return data;
    if (typeof data !== 'object') return String(data);

    const lines = [];
    const formatValue = (val, indent = 0) => {
      const prefix = '  '.repeat(indent);
      if (Array.isArray(val)) {
        return val.map(v => prefix + '- ' + formatValue(v, 0)).join('\n');
      } else if (val && typeof val === 'object') {
        return Object.entries(val)
          .map(([k, v]) => `${prefix}${k}: ${formatValue(v, 0)}`)
          .join('\n');
      }
      return String(val);
    };

    for (const [key, value] of Object.entries(data)) {
      lines.push(`${key}:`);
      lines.push(formatValue(value, 1));
      lines.push('');
    }

    return lines.join('\n');
  } catch (err) {
    console.error(`[Warden] Error formatting as text: ${err.message}`);
    return JSON.stringify(data, null, 2);
  }
}

/**
 * Format report data as CSV.
 */
function formatAsCSV(data) {
  try {
    if (typeof data === 'string') return data;

    // Handle array of objects
    if (Array.isArray(data) && data.length > 0 && typeof data[0] === 'object') {
      const headers = Object.keys(data[0]);
      const rows = data.map(row =>
        headers.map(h => csvEscape(row[h])).join(',')
      );
      return [headers.join(','), ...rows].join('\n');
    }

    // Handle single object
    if (data && typeof data === 'object') {
      const entries = Object.entries(data);
      return entries.map(([k, v]) => `${csvEscape(k)},${csvEscape(v)}`).join('\n');
    }

    return String(data);
  } catch (err) {
    console.error(`[Warden] Error formatting as CSV: ${err.message}`);
    return JSON.stringify(data);
  }
}

/**
 * Format report data as HTML.
 */
function formatAsHTML(data) {
  try {
    if (typeof data === 'string') return `<pre>${escapeHtml(data)}</pre>`;

    const html = [];
    html.push('<!DOCTYPE html>');
    html.push('<html><head>');
    html.push('<meta charset="UTF-8">');
    html.push('<title>Warden Compliance Report</title>');
    html.push('<style>');
    html.push('body { font-family: Arial, sans-serif; margin: 20px; }');
    html.push('table { border-collapse: collapse; width: 100%; margin: 10px 0; }');
    html.push('th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }');
    html.push('th { background-color: #4CAF50; color: white; }');
    html.push('h1 { color: #333; }');
    html.push('h2 { color: #666; margin-top: 20px; }');
    html.push('</style>');
    html.push('</head><body>');
    html.push('<h1>Warden Compliance Report</h1>');

    const formatValue = (val) => {
      if (Array.isArray(val)) {
        if (val.length === 0) return '<em>None</em>';
        if (typeof val[0] === 'object') {
          const headers = Object.keys(val[0]);
          let table = '<table><thead><tr>';
          table += headers.map(h => `<th>${escapeHtml(h)}</th>`).join('');
          table += '</tr></thead><tbody>';
          for (const row of val) {
            table += '<tr>';
            table += headers.map(h => `<td>${escapeHtml(String(row[h] || ''))}</td>`).join('');
            table += '</tr>';
          }
          table += '</tbody></table>';
          return table;
        }
        return '<ul>' + val.map(v => `<li>${escapeHtml(String(v))}</li>`).join('') + '</ul>';
      } else if (val && typeof val === 'object') {
        return '<ul>' + Object.entries(val)
          .map(([k, v]) => `<li><strong>${escapeHtml(k)}:</strong> ${formatValue(v)}</li>`)
          .join('') + '</ul>';
      }
      return escapeHtml(String(val));
    };

    for (const [key, value] of Object.entries(data)) {
      html.push(`<h2>${escapeHtml(key)}</h2>`);
      html.push(formatValue(value));
    }

    html.push('</body></html>');
    return html.join('\n');
  } catch (err) {
    console.error(`[Warden] Error formatting as HTML: ${err.message}`);
    return `<pre>${JSON.stringify(data, null, 2)}</pre>`;
  }
}

function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}
