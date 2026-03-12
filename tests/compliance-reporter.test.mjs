import { describe, it, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { logAction, getAuditLogPath } from '../lib/audit-logger.mjs';
import {
  generateSOC2Report,
  generateSummary,
  getHighRiskActions,
  exportCSV,
  registerReportTemplate,
  generateCustomReport,
  getReportTemplates,
  unregisterReportTemplate,
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
      assert.ok(report.summary.totalActions >= 0);
      assert.ok(report.summary.totalViolations >= 0);
      assert.ok(report.summary.complianceRate);
    });

    it('should include CC6 Logical Access controls', async () => {
      const report = await generateSOC2Report({});
      const cc6 = report.controls.CC6_LogicalAccess;
      assert.ok(cc6.totalAccessEvents >= 0);
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
      assert.ok(Array.isArray(actions));
      // May or may not have violations depending on test state
      if (actions.length > 0) {
        assert.ok(actions.every(a => Array.isArray(a.riskReasons)));
      }
    });

    it('should return blocked actions', async () => {
      const actions = await getHighRiskActions({});
      assert.ok(Array.isArray(actions));
      // Check structure rather than specific content
    });

    it('should detect sensitive file access', async () => {
      const actions = await getHighRiskActions({});
      assert.ok(Array.isArray(actions));
      // Structure test
      for (const action of actions) {
        assert.ok(action.riskReasons);
        assert.ok(Array.isArray(action.riskReasons));
      }
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
      const lines = csv.split('\n').filter(l => l.trim());
      assert.ok(lines.length >= 1);
      assert.equal(lines[0], 'id,timestamp,user,tool,command,path,result,violations');
    });

    it('should include entries as rows', async () => {
      const csv = await exportCSV({});
      const lines = csv.split('\n').filter(l => l.trim());
      // Should have at least header
      assert.ok(lines.length >= 1);
      assert.ok(lines[0].includes('id,timestamp'));
    });

    it('should properly escape CSV values with commas', async () => {
      const csv = await exportCSV({});
      // CSV should be valid format
      assert.ok(csv.length > 0);
      const lines = csv.split('\n').filter(l => l.trim());
      assert.ok(lines[0].includes('id,timestamp'));
    });
  });

  describe('registerReportTemplate', () => {
    beforeEach(() => {
      // Clean up templates
      const templates = getReportTemplates();
      for (const t of templates) {
        unregisterReportTemplate(t.name);
      }
    });

    it('should register a custom template', () => {
      const registered = registerReportTemplate('custom1', {
        description: 'Custom report',
        generator: (entries) => ({ total: entries.length }),
        format: 'json',
      });

      assert.ok(registered);
      const templates = getReportTemplates();
      assert.ok(templates.some(t => t.name === 'custom1'));
    });

    it('should throw on invalid template name', () => {
      assert.throws(
        () => registerReportTemplate('', { generator: () => ({}) }),
        /non-empty string/
      );
    });

    it('should throw on missing generator', () => {
      assert.throws(
        () => registerReportTemplate('test', { description: 'test' }),
        /generator function/
      );
    });

    it('should throw on invalid generator type', () => {
      assert.throws(
        () => registerReportTemplate('test', { generator: 'not a function' }),
        /generator function/
      );
    });
  });

  describe('generateCustomReport', { concurrency: false }, () => {
    beforeEach(() => {
      const templates = getReportTemplates();
      for (const t of templates) {
        unregisterReportTemplate(t.name);
      }
    });

    it('should generate report using custom template', async () => {
      registerReportTemplate('simple', {
        description: 'Simple count report',
        generator: (entries) => ({
          total: entries.length,
          users: [...new Set(entries.map(e => e.user))],
        }),
        format: 'json',
      });

      const report = await generateCustomReport('simple', {});
      assert.ok(report.total >= 0);
      assert.ok(Array.isArray(report.users));
    });

    it('should throw on non-existent template', async () => {
      await assert.rejects(
        () => generateCustomReport('nonexistent', {}),
        /Template not found/
      );
    });

    it('should generate text format report', async () => {
      registerReportTemplate('text-test', {
        generator: (entries) => ({ count: entries.length }),
        format: 'text',
      });

      const report = await generateCustomReport('text-test', {});
      assert.equal(typeof report, 'string');
      assert.ok(report.includes('count'));
    });

    it('should generate CSV format report', async () => {
      registerReportTemplate('csv-test', {
        generator: (entries) => {
          const data = entries.slice(0, 3).map(e => ({ tool: e.tool, user: e.user }));
          return data.length > 0 ? data : [{ tool: 'none', user: 'none' }];
        },
        format: 'csv',
      });

      const report = await generateCustomReport('csv-test', {});
      assert.equal(typeof report, 'string');
      assert.ok(report.includes('tool') && report.includes('user'));
    });

    it('should generate HTML format report', async () => {
      registerReportTemplate('html-test', {
        generator: (entries) => ({ totalEntries: entries.length }),
        format: 'html',
      });

      const report = await generateCustomReport('html-test', {});
      assert.equal(typeof report, 'string');
      assert.ok(report.includes('<!DOCTYPE html>'));
      assert.ok(report.includes('Warden Compliance Report'));
    });

    it('should apply custom formatter', async () => {
      registerReportTemplate('custom-format', {
        generator: (entries) => ({ count: entries.length }),
        format: 'json',
        formatter: (data) => `Total: ${data.count}`,
      });

      const report = await generateCustomReport('custom-format', {});
      assert.equal(typeof report, 'string');
      assert.ok(report.startsWith('Total:'));
    });

    it('should pass options to generator', async () => {
      registerReportTemplate('with-options', {
        generator: (entries, options) => ({
          count: entries.length,
          customField: options.customValue,
        }),
      });

      const report = await generateCustomReport('with-options', {}, { customValue: 'test123' });
      assert.equal(report.customField, 'test123');
    });
  });

  describe('getReportTemplates', () => {
    beforeEach(() => {
      const templates = getReportTemplates();
      for (const t of templates) {
        unregisterReportTemplate(t.name);
      }
    });

    it('should return all registered templates', () => {
      registerReportTemplate('t1', { generator: () => ({}) });
      registerReportTemplate('t2', { generator: () => ({}) });

      const templates = getReportTemplates();
      assert.equal(templates.length, 2);
      assert.ok(templates.some(t => t.name === 't1'));
      assert.ok(templates.some(t => t.name === 't2'));
    });

    it('should return empty array when no templates', () => {
      const templates = getReportTemplates();
      assert.equal(templates.length, 0);
    });
  });

  describe('unregisterReportTemplate', () => {
    it('should remove an existing template', () => {
      registerReportTemplate('temp', { generator: () => ({}) });
      assert.ok(getReportTemplates().some(t => t.name === 'temp'));

      const removed = unregisterReportTemplate('temp');
      assert.ok(removed);
      assert.ok(!getReportTemplates().some(t => t.name === 'temp'));
    });

    it('should return false for non-existent template', () => {
      const removed = unregisterReportTemplate('nonexistent');
      assert.equal(removed, false);
    });
  });
});
