/**
 * Warden Audit Logger
 * Complete audit trail with JSONL backend.
 */

import { appendFile, readFile, mkdir, writeFile, stat, rename, readdir, unlink } from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { createGzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { homedir } from 'node:os';
import { join, dirname, basename } from 'node:path';

const AUDIT_DIR = join(homedir(), '.warden');
const AUDIT_LOG = join(AUDIT_DIR, 'audit.jsonl');

/**
 * Ensure the audit directory and log file exist.
 */
async function ensureAuditLog() {
  try {
    await mkdir(AUDIT_DIR, { recursive: true });
  } catch (err) {
    if (err.code !== 'EEXIST') {
      console.warn(`[Warden] Failed to create audit directory: ${err.message}`);
    }
  }
  try {
    await stat(AUDIT_LOG);
  } catch {
    try {
      await writeFile(AUDIT_LOG, '', 'utf-8');
    } catch (err) {
      console.warn(`[Warden] Failed to create audit log: ${err.message}`);
    }
  }
}

/**
 * Log an action to the audit trail.
 *
 * @param {object} action — { tool, command, path, params, user, result, ... }
 * @returns {Promise<object>} the logged entry
 */
export async function logAction(action) {
  try {
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

    try {
      await appendFile(AUDIT_LOG, JSON.stringify(entry) + '\n', 'utf-8');
    } catch (err) {
      if (err.code === 'ENOSPC') {
        console.error(`[Warden] Disk full - cannot write to audit log: ${err.message}`);
      } else if (err.code === 'EACCES' || err.code === 'EPERM') {
        console.error(`[Warden] Permission denied - cannot write to audit log: ${err.message}`);
      } else {
        console.error(`[Warden] Failed to write to audit log: ${err.message}`);
      }
      throw err;
    }
    return entry;
  } catch (err) {
    console.error(`[Warden] Failed to log action: ${err.message}`);
    throw err;
  }
}

/**
 * Read all log entries, optionally applying filters.
 *
 * @param {object} [filters] — { user?, tool?, result?, startDate?, endDate?, path? }
 * @returns {Promise<Array<object>>}
 */
export async function queryLog(filters = {}) {
  try {
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
  } catch (err) {
    console.error(`[Warden] Failed to query log: ${err.message}`);
    return [];
  }
}

/**
 * Generate a compliance report for a given period.
 *
 * @param {object} period — { startDate, endDate }
 * @param {string} [format="json"] — "json" or "text"
 * @returns {Promise<object|string>}
 */
export async function generateReport(period, format = 'json') {
  try {
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
  } catch (err) {
    console.error(`[Warden] Failed to generate report: ${err.message}`);
    throw err;
  }
}

/**
 * Get statistics for a given period.
 *
 * @param {object} period — { startDate?, endDate? }
 * @returns {Promise<object>}
 */
export async function getStats(period = {}) {
  try {
    const entries = await queryLog(period);
    return computeStats(entries);
  } catch (err) {
    console.error(`[Warden] Failed to get stats: ${err.message}`);
    throw err;
  }
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

/**
 * Rotate the audit log file if it exceeds a size threshold.
 *
 * @param {object} [options] — Rotation options
 * @param {number} [options.maxSizeBytes=10485760] — Max log size before rotation (default 10MB)
 * @param {number} [options.maxBackups=5] — Max number of backup files to keep
 * @param {boolean} [options.compress=true] — Whether to compress rotated logs
 * @returns {Promise<{ rotated: boolean, newBackupPath?: string }>}
 */
export async function rotateLog(options = {}) {
  try {
    const {
      maxSizeBytes = 10 * 1024 * 1024, // 10MB default
      maxBackups = 5,
      compress = true,
    } = options;

    await ensureAuditLog();

    // Check current log size
    let fileStats;
    try {
      fileStats = await stat(AUDIT_LOG);
    } catch {
      return { rotated: false };
    }

    if (fileStats.size < maxSizeBytes) {
      return { rotated: false };
    }

    // Generate timestamp-based backup filename
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupExt = compress ? '.jsonl.gz' : '.jsonl';
    const backupPath = join(AUDIT_DIR, `audit-${timestamp}${backupExt}`);

    // Rotate the log
    if (compress) {
      // Compress while rotating
      await compressFile(AUDIT_LOG, backupPath);
      // Clear the original log
      await writeFile(AUDIT_LOG, '', 'utf-8');
    } else {
      // Simple rename
      await rename(AUDIT_LOG, backupPath);
      // Create new empty log
      await writeFile(AUDIT_LOG, '', 'utf-8');
    }

    // Clean up old backups
    await cleanupOldBackups(maxBackups, compress);

    return {
      rotated: true,
      newBackupPath: backupPath,
      sizeBytes: fileStats.size,
    };
  } catch (err) {
    console.error(`[Warden] Failed to rotate log: ${err.message}`);
    throw err;
  }
}

/**
 * Compress a file using gzip.
 *
 * @param {string} sourcePath — Path to source file
 * @param {string} destPath — Path to compressed destination file
 * @returns {Promise<void>}
 */
async function compressFile(sourcePath, destPath) {
  try {
    const source = createReadStream(sourcePath);
    const destination = createWriteStream(destPath);
    const gzip = createGzip({ level: 9 });

    await pipeline(source, gzip, destination);
  } catch (err) {
    console.error(`[Warden] Failed to compress file: ${err.message}`);
    throw err;
  }
}

/**
 * Clean up old backup files, keeping only the most recent ones.
 *
 * @param {number} maxBackups — Maximum number of backups to keep
 * @param {boolean} compressed — Whether backups are compressed
 * @returns {Promise<number>} Number of files deleted
 */
async function cleanupOldBackups(maxBackups, compressed) {
  try {
    const files = await readdir(AUDIT_DIR);
    const pattern = compressed ? /^audit-.*\.jsonl\.gz$/ : /^audit-.*\.jsonl$/;

    const backups = files
      .filter(f => pattern.test(f))
      .map(f => ({
        name: f,
        path: join(AUDIT_DIR, f),
      }))
      .sort((a, b) => b.name.localeCompare(a.name)); // newest first

    let deletedCount = 0;
    if (backups.length > maxBackups) {
      const toDelete = backups.slice(maxBackups);
      for (const backup of toDelete) {
        try {
          await unlink(backup.path);
          deletedCount++;
        } catch (err) {
          console.warn(`[Warden] Failed to delete old backup ${backup.name}: ${err.message}`);
        }
      }
    }

    return deletedCount;
  } catch (err) {
    console.error(`[Warden] Failed to cleanup old backups: ${err.message}`);
    return 0;
  }
}

/**
 * Automatically rotate log before writing if needed.
 *
 * @param {object} action — Action to log
 * @param {object} [rotationOptions] — Rotation options (see rotateLog)
 * @returns {Promise<{ entry: object, rotated: boolean }>}
 */
export async function logActionWithRotation(action, rotationOptions = {}) {
  try {
    // Check and rotate if needed
    const rotationResult = await rotateLog(rotationOptions);

    // Log the action
    const entry = await logAction(action);

    return {
      entry,
      rotated: rotationResult.rotated,
      backupPath: rotationResult.newBackupPath,
    };
  } catch (err) {
    console.error(`[Warden] Failed to log action with rotation: ${err.message}`);
    throw err;
  }
}

/**
 * Get list of all backup log files.
 *
 * @returns {Promise<Array<{ name: string, path: string, compressed: boolean, stats: object }>>}
 */
export async function getBackupLogs() {
  try {
    await mkdir(AUDIT_DIR, { recursive: true });
    const files = await readdir(AUDIT_DIR);

    const backups = [];
    for (const file of files) {
      if (/^audit-.*\.jsonl(\.gz)?$/.test(file)) {
        const filePath = join(AUDIT_DIR, file);
        try {
          const stats = await stat(filePath);
          backups.push({
            name: file,
            path: filePath,
            compressed: file.endsWith('.gz'),
            sizeBytes: stats.size,
            modified: stats.mtime,
          });
        } catch {
          // Skip files we can't stat
        }
      }
    }

    return backups.sort((a, b) => b.modified - a.modified);
  } catch (err) {
    console.error(`[Warden] Failed to get backup logs: ${err.message}`);
    return [];
  }
}

/**
 * Search audit log entries by text content.
 *
 * @param {string} searchTerm — Text to search for in log entries
 * @param {object} [options={}] — Search options
 * @param {number} [options.limit=50] — Max results
 * @param {boolean} [options.caseSensitive=false] — Case sensitive search
 * @returns {Promise<object[]>} Matching log entries
 */
export async function searchLog(searchTerm, options = {}) {
  try {
    const { limit = 50, caseSensitive = false } = options;
    const entries = await queryLog({});
    const term = caseSensitive ? searchTerm : searchTerm.toLowerCase();

    return entries
      .filter(entry => {
        const text = JSON.stringify(entry);
        return caseSensitive ? text.includes(term) : text.toLowerCase().includes(term);
      })
      .slice(0, limit);
  } catch (err) {
    console.error(`[Warden] Failed to search log: ${err.message}`);
    return [];
  }
}
