import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, stat, readFile } from 'node:fs/promises';
import { logAction, queryLog, generateReport, getStats, getAuditLogPath, rotateLog, logActionWithRotation, getBackupLogs } from '../lib/audit-logger.mjs';

describe('audit-logger', { concurrency: false }, () => {
  const auditPath = getAuditLogPath();

  describe('logAction', { concurrency: false }, () => {
    before(async () => {
      await writeFile(auditPath, '', 'utf-8');
    });

    it('should log an action and return the entry', async () => {
      await writeFile(auditPath, '', 'utf-8');
      const entry = await logAction({
        tool: 'Bash',
        command: 'echo hello',
        result: 'success',
        user: 'testuser',
      });

      assert.ok(entry.id);
      assert.ok(entry.timestamp);
      assert.equal(entry.tool, 'Bash');
      assert.equal(entry.command, 'echo hello');
      assert.equal(entry.result, 'success');
      assert.equal(entry.user, 'testuser');
    });

    it('should auto-fill defaults for missing fields', async () => {
      await writeFile(auditPath, '', 'utf-8');
      const entry = await logAction({ tool: 'Read' });
      assert.ok(entry.id);
      assert.ok(entry.timestamp);
      assert.equal(entry.tool, 'Read');
      assert.equal(entry.command, null);
      assert.ok(entry.user);
    });

    it('should persist entries to the JSONL file', async () => {
      await writeFile(auditPath, '', 'utf-8');
      await logAction({ tool: 'Write', path: '/app/test.js', result: 'success', user: 'testpersist' });
      await logAction({ tool: 'Bash', command: 'npm test', result: 'success', user: 'testpersist' });

      const entries = await queryLog({ user: 'testpersist' });
      assert.ok(entries.length >= 2);
    });

    it('should include violations when provided', async () => {
      const entry = await logAction({
        tool: 'Bash',
        command: 'rm -rf /',
        result: 'blocked',
        violations: [{ policy: 'safety', severity: 'critical' }],
      });

      assert.equal(entry.violations.length, 1);
      assert.equal(entry.violations[0].policy, 'safety');
    });
  });

  describe('queryLog', { concurrency: false }, () => {
    const queryTestUser = 'querytest-' + Date.now();

    before(async () => {
      await writeFile(auditPath, '', 'utf-8');
      await logAction({ tool: 'Bash', command: 'echo 1', result: 'success', user: queryTestUser });
      await logAction({ tool: 'Write', path: '/app/a.js', result: 'success', user: queryTestUser + '-bob' });
      await logAction({ tool: 'Bash', command: 'rm -rf /', result: 'blocked', user: queryTestUser });
      await logAction({ tool: 'Read', path: '/app/b.js', result: 'success', user: queryTestUser });
    });

    it('should return all entries with no filters', async () => {
      const entries = await queryLog({ user: queryTestUser });
      assert.equal(entries.length, 3);
    });

    it('should filter by user', async () => {
      const entries = await queryLog({ user: queryTestUser });
      assert.equal(entries.length, 3);
      assert.ok(entries.every(e => e.user === queryTestUser));
    });

    it('should filter by tool', async () => {
      const entries = await queryLog({ user: queryTestUser, tool: 'Bash' });
      assert.equal(entries.length, 2);
      assert.ok(entries.every(e => e.tool === 'Bash'));
    });

    it('should filter by result', async () => {
      const entries = await queryLog({ user: queryTestUser, result: 'blocked' });
      assert.equal(entries.length, 1);
      assert.ok(entries.every(e => e.result === 'blocked'));
    });

    it('should filter by path prefix', async () => {
      const entries = await queryLog({ path: '/app/' });
      assert.equal(entries.length, 2);
    });

    it('should filter by date range', async () => {
      const entries = await queryLog({
        user: queryTestUser,
        startDate: new Date(Date.now() - 60000).toISOString(),
        endDate: new Date(Date.now() + 60000).toISOString(),
      });
      assert.ok(entries.length >= 3);
    });

    it('should return empty for future date range', async () => {
      const future = new Date(Date.now() + 86400000).toISOString();
      const entries = await queryLog({ startDate: future });
      assert.equal(entries.length, 0);
    });
  });

  describe('generateReport', { concurrency: false }, () => {
    before(async () => {
      await writeFile(auditPath, '', 'utf-8');
      await logAction({ tool: 'Bash', command: 'echo hi', result: 'success', user: 'alice' });
      await logAction({ tool: 'Write', path: '/app/x.js', result: 'success', user: 'bob' });
      await logAction({
        tool: 'Bash', command: 'rm -rf /', result: 'blocked', user: 'alice',
        violations: [{ policy: 'safety' }],
      });
    });

    it('should generate a JSON report', async () => {
      const report = await generateReport({});
      assert.equal(report.totalActions, 3);
      assert.equal(report.totalViolations, 1);
      assert.ok(report.stats);
      assert.ok(report.generatedAt);
    });

    it('should generate a text report', async () => {
      const text = await generateReport({}, 'text');
      assert.ok(typeof text === 'string');
      assert.ok(text.includes('WARDEN COMPLIANCE REPORT'));
      assert.ok(text.includes('Total Actions'));
    });
  });

  describe('getStats', { concurrency: false }, () => {
    it('should return stats with top tools', async () => {
      const stats = await getStats();
      assert.ok(stats.totalActions > 0);
      assert.ok(Array.isArray(stats.topTools));
      assert.ok(stats.topTools.length > 0);
      assert.ok(stats.userCounts);
    });
  });

  describe('rotateLog', { concurrency: false }, () => {
    it('should not rotate if log is under size threshold', async () => {
      await writeFile(auditPath, 'small log\n', 'utf-8');
      const result = await rotateLog({ maxSizeBytes: 1000000 });
      assert.equal(result.rotated, false);
    });

    it('should rotate log when it exceeds size threshold', async () => {
      // Create a large log file
      const largeContent = 'x'.repeat(1024) + '\n';
      let content = '';
      for (let i = 0; i < 100; i++) {
        content += largeContent;
      }
      await writeFile(auditPath, content, 'utf-8');

      const result = await rotateLog({ maxSizeBytes: 1000, compress: false });
      assert.equal(result.rotated, true);
      assert.ok(result.newBackupPath);
      assert.ok(result.sizeBytes > 1000);

      // Verify new log is small (may not be exactly 0 due to concurrent writes)
      const stats = await stat(auditPath);
      assert.ok(stats.size < 1000);
    });

    it('should compress rotated logs', async () => {
      const content = 'test log entry\n'.repeat(1000);
      await writeFile(auditPath, content, 'utf-8');

      const result = await rotateLog({ maxSizeBytes: 100, compress: true });
      assert.equal(result.rotated, true);
      assert.ok(result.newBackupPath.endsWith('.gz'));
    });

    it('should clean up old backups', async () => {
      await writeFile(auditPath, 'x'.repeat(2000), 'utf-8');

      // Create multiple rotations
      await rotateLog({ maxSizeBytes: 100, maxBackups: 2, compress: false });
      await writeFile(auditPath, 'x'.repeat(2000), 'utf-8');
      await rotateLog({ maxSizeBytes: 100, maxBackups: 2, compress: false });
      await writeFile(auditPath, 'x'.repeat(2000), 'utf-8');
      await rotateLog({ maxSizeBytes: 100, maxBackups: 2, compress: false });

      const backups = await getBackupLogs();
      const uncompressed = backups.filter(b => !b.compressed);
      assert.ok(uncompressed.length <= 2, 'Should keep at most 2 backups');
    });

    it('should handle rotation with custom options', async () => {
      await writeFile(auditPath, 'x'.repeat(5000), 'utf-8');
      const result = await rotateLog({
        maxSizeBytes: 1000,
        maxBackups: 3,
        compress: true,
      });
      assert.equal(result.rotated, true);
    });
  });

  describe('logActionWithRotation', { concurrency: false }, () => {
    it('should log and rotate in one call', async () => {
      await writeFile(auditPath, 'x'.repeat(5000), 'utf-8');
      const result = await logActionWithRotation(
        { tool: 'Test', command: 'test' },
        { maxSizeBytes: 1000, compress: false }
      );

      assert.ok(result.entry);
      assert.ok(result.rotated);
      assert.ok(result.backupPath);
    });

    it('should not rotate if under threshold', async () => {
      await writeFile(auditPath, 'small\n', 'utf-8');
      const result = await logActionWithRotation(
        { tool: 'Test', command: 'test' },
        { maxSizeBytes: 100000 }
      );

      assert.ok(result.entry);
      assert.equal(result.rotated, false);
    });
  });

  describe('getBackupLogs', { concurrency: false }, () => {
    it('should list all backup log files', async () => {
      await writeFile(auditPath, 'x'.repeat(2000), 'utf-8');
      await rotateLog({ maxSizeBytes: 100, compress: false });

      const backups = await getBackupLogs();
      assert.ok(Array.isArray(backups));
      assert.ok(backups.length > 0);
      assert.ok(backups[0].name);
      assert.ok(backups[0].path);
      assert.ok('compressed' in backups[0]);
      assert.ok(backups[0].sizeBytes > 0);
    });

    it('should sort backups by modification time', async () => {
      const backups = await getBackupLogs();
      if (backups.length > 1) {
        // Should be sorted newest first
        assert.ok(backups[0].modified >= backups[backups.length - 1].modified);
      }
    });
  });
});
