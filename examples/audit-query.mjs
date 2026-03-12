#!/usr/bin/env node
/**
 * Audit Query — Query and analyze the Warden audit log
 *
 * Demonstrates querying audit logs, generating compliance reports,
 * and exporting data for external auditors.
 *
 * Usage: node examples/audit-query.mjs
 */
import { logAction, queryLog, generateReport, getStats } from '../lib/audit-logger.mjs';
import { generateSummary, generateSOC2Report, exportCSV } from '../lib/compliance-reporter.mjs';

console.log('=== Warden Audit Query ===\n');

// First, create some sample audit entries
const sampleActions = [
  { type: 'command', command: 'git commit -m "fix auth bug"', result: 'allowed', timestamp: new Date().toISOString() },
  { type: 'file_write', file: 'src/auth.js', result: 'allowed', timestamp: new Date().toISOString() },
  { type: 'command', command: 'rm -rf /tmp/build', result: 'allowed', timestamp: new Date().toISOString() },
  { type: 'file_write', file: '.env.local', result: 'blocked', reason: 'env file protection', timestamp: new Date().toISOString() },
  { type: 'command', command: 'git push --force origin main', result: 'blocked', reason: 'force push to main', timestamp: new Date().toISOString() },
];

console.log('Logging sample actions...');
for (const action of sampleActions) {
  await logAction(action);
}
console.log(`Logged ${sampleActions.length} actions\n`);

// Query the audit log
console.log('--- Query: All Blocked Actions ---\n');
const blocked = await queryLog({ result: 'blocked' });
blocked.forEach(entry => {
  console.log(`  [BLOCKED] ${entry.command || entry.file} — ${entry.reason}`);
});

// Get statistics
const period = {
  start: new Date(Date.now() - 86400000).toISOString(),
  end: new Date().toISOString()
};

console.log('\n--- Audit Statistics ---\n');
const stats = await getStats(period);
console.log(`  Total actions: ${stats.totalActions}`);
console.log(`  Allowed: ${stats.resultCounts?.allowed || 0}`);
console.log(`  Blocked: ${stats.resultCounts?.blocked || 0}`);
console.log(`  Violation count: ${stats.violationCount}`);

// Generate compliance report
console.log('\n--- Compliance Summary ---\n');
const summary = await generateSummary(period);
console.log(JSON.stringify(summary, null, 2));

// Export for external auditors
console.log('\n--- CSV Export (first 5 lines) ---\n');
const csv = await exportCSV(period);
const csvLines = csv.split('\n').slice(0, 6);
console.log(csvLines.join('\n'));
