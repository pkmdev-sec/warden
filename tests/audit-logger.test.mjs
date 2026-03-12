import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { logAction, queryLog, generateReport, getStats, getAuditLogPath } from '../lib/audit-logger.mjs';

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
      await logAction({ tool: 'Write', path: '/app/test.js', result: 'success' });
      await logAction({ tool: 'Bash', command: 'npm test', result: 'success' });

      const entries = await queryLog();
      assert.equal(entries.length, 2);
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
    before(async () => {
      await writeFile(auditPath, '', 'utf-8');
      await logAction({ tool: 'Bash', command: 'echo 1', result: 'success', user: 'alice' });
      await logAction({ tool: 'Write', path: '/app/a.js', result: 'success', user: 'bob' });
      await logAction({ tool: 'Bash', command: 'rm -rf /', result: 'blocked', user: 'alice' });
      await logAction({ tool: 'Read', path: '/app/b.js', result: 'success', user: 'alice' });
    });

    it('should return all entries with no filters', async () => {
      const entries = await queryLog();
      assert.equal(entries.length, 4);
    });

    it('should filter by user', async () => {
      const entries = await queryLog({ user: 'alice' });
      assert.equal(entries.length, 3);
    });

    it('should filter by tool', async () => {
      const entries = await queryLog({ tool: 'Bash' });
      assert.equal(entries.length, 2);
    });

    it('should filter by result', async () => {
      const entries = await queryLog({ result: 'blocked' });
      assert.equal(entries.length, 1);
    });

    it('should filter by path prefix', async () => {
      const entries = await queryLog({ path: '/app/' });
      assert.equal(entries.length, 2);
    });

    it('should filter by date range', async () => {
      const entries = await queryLog({
        startDate: new Date(Date.now() - 60000).toISOString(),
        endDate: new Date(Date.now() + 60000).toISOString(),
      });
      assert.equal(entries.length, 4);
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
});
