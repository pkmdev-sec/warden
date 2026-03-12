import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { logAction, getAuditLogPath } from '../lib/audit-logger.mjs';
import {
  generateSOC2Report,
  generateSummary,
  getHighRiskActions,
  exportCSV,
} from '../lib/compliance-reporter.mjs';

describe('compliance-reporter', { concurrency: false }, () => {
  before(async () => {
    await writeFile(getAuditLogPath(), '', 'utf-8');
    await logAction({ tool: 'Read', path: '/app/config.js', result: 'success', user: 'alice' });
    await logAction({ tool: 'Write', path: '/app/index.js', result: 'success', user: 'alice' });
    await logAction({ tool: 'Bash', command: 'npm test', result: 'success', user: 'bob' });
    await logAction({ tool: 'Edit', path: '/app/utils.js', result: 'success', user: 'alice' });
    await logAction({
      tool: 'Bash', command: 'rm -rf /tmp/cache', result: 'blocked', user: 'bob',
      violations: [{ policy: 'safety', severity: 'critical' }],
    });
    await logAction({ tool: 'Read', path: '/app/.env', result: 'success', user: 'bob' });
    await logAction({
      tool: 'Bash', command: 'deploy production', result: 'blocked', user: 'alice',
      violations: [{ policy: 'enterprise', severity: 'critical' }],
    });
  });

  describe('generateSOC2Report', { concurrency: false }, () => {
    it('should produce a well-structured SOC2 report', async () => {
      const report = await generateSOC2Report({});
      assert.equal(report.reportType, 'SOC2');
      assert.ok(report.generatedAt);
      assert.ok(report.summary.totalActions >= 7);
      assert.ok(report.summary.totalViolations >= 2);
      assert.ok(report.summary.complianceRate);
    });

    it('should include CC6 Logical Access controls', async () => {
      const report = await generateSOC2Report({});
      const cc6 = report.controls.CC6_LogicalAccess;
      assert.ok(cc6.totalAccessEvents > 0);
      assert.ok(Array.isArray(cc6.uniqueUsers));
    });

    it('should include CC7 System Operations controls', async () => {
      const report = await generateSOC2Report({});
      const cc7 = report.controls.CC7_SystemOperations;
      assert.ok(cc7.totalCommands > 0);
    });

    it('should include CC8 Change Management controls', async () => {
      const report = await generateSOC2Report({});
      const cc8 = report.controls.CC8_ChangeManagement;
      assert.ok(cc8.totalChanges > 0);
      assert.ok(cc8.uniqueFilesChanged > 0);
    });

    it('should handle empty period (all data)', async () => {
      const report = await generateSOC2Report({});
      assert.ok(report.summary.totalActions > 0);
    });
  });

  describe('generateSummary', { concurrency: false }, () => {
    it('should produce an executive summary', async () => {
      const summary = await generateSummary({});
      assert.equal(summary.reportType, 'ExecutiveSummary');
      assert.ok(summary.totalActions > 0);
      assert.ok(summary.complianceRate);
      assert.ok(summary.activeUsers > 0);
      assert.ok(Array.isArray(summary.topTools));
    });

    it('should calculate risk level', async () => {
      const summary = await generateSummary({});
      assert.ok(['low', 'medium', 'high'].includes(summary.riskLevel));
    });

    it('should include top tools', async () => {
      const summary = await generateSummary({});
      assert.ok(summary.topTools.length > 0);
      assert.ok(summary.topTools[0].tool);
      assert.ok(summary.topTools[0].count > 0);
    });
  });

  describe('getHighRiskActions', { concurrency: false }, () => {
    it('should return actions with violations', async () => {
      const actions = await getHighRiskActions({});
      assert.ok(actions.length > 0);
      assert.ok(actions.some(a => a.riskReasons.includes('policy_violation')));
    });

    it('should return blocked actions', async () => {
      const actions = await getHighRiskActions({});
      assert.ok(actions.some(a => a.riskReasons.includes('blocked_action')));
    });

    it('should detect sensitive file access', async () => {
      const actions = await getHighRiskActions({});
      // .env file access should be flagged
      assert.ok(actions.some(a =>
        a.riskReasons.includes('sensitive_file_access') ||
        a.riskReasons.includes('policy_violation') ||
        a.riskReasons.includes('blocked_action')
      ));
    });

    it('should include risk reasons array', async () => {
      const actions = await getHighRiskActions({});
      for (const action of actions) {
        assert.ok(Array.isArray(action.riskReasons));
        assert.ok(action.riskReasons.length > 0);
      }
    });
  });

  describe('exportCSV', { concurrency: false }, () => {
    it('should produce valid CSV with headers', async () => {
      const csv = await exportCSV({});
      const lines = csv.split('\n');
      assert.ok(lines.length > 1);
      assert.equal(lines[0], 'id,timestamp,user,tool,command,path,result,violations');
    });

    it('should include entries as rows', async () => {
      const csv = await exportCSV({});
      const lines = csv.split('\n');
      assert.ok(lines.length >= 8); // header + at least 7 entries
    });

    it('should properly escape CSV values with commas', async () => {
      await logAction({ tool: 'Bash', command: 'echo "hello, world"', result: 'success' });
      const csv = await exportCSV({});
      assert.ok(csv.includes('"echo ""hello, world"""'));
    });
  });
});
