#!/usr/bin/env node
/**
 * Enterprise Setup — Configure Warden for enterprise policy enforcement
 *
 * Demonstrates loading multiple policy layers, composing policies,
 * and setting up comprehensive access control.
 *
 * Usage: node examples/enterprise-setup.mjs
 */
import { loadPolicies, evaluateAction, composePolicies, evaluateComposedPolicy } from '../lib/policy-engine.mjs';
import { addRule, addRules, checkFileAccess, checkCommandAccess } from '../lib/access-control.mjs';
import { classifyContent, classifyFile } from '../lib/data-classifier.mjs';
import { logAction } from '../lib/audit-logger.mjs';

console.log('=== Warden Enterprise Setup ===\n');

// Step 1: Load base policies
console.log('--- Loading Policies ---\n');
const policies = await loadPolicies(new URL('../policies', import.meta.url).pathname);
console.log(`Loaded ${policies.size || Object.keys(policies).length} policy files`);

// Step 2: Set up access control rules
console.log('\n--- Configuring Access Control ---\n');

addRules([
  { type: 'file', pattern: '/etc/**', action: 'block', options: { reason: 'System files protected' } },
  { type: 'file', pattern: '**/.env*', action: 'block', options: { operation: 'write', reason: 'Env files read-only' } },
  { type: 'file', pattern: '**/node_modules/**', action: 'block', options: { operation: 'write', reason: 'No direct node_modules edits' } },
  { type: 'command', pattern: 'rm -rf /*', action: 'block', options: { reason: 'Destructive root delete blocked' } },
  { type: 'command', pattern: 'curl*|*sh', action: 'block', options: { reason: 'Pipe to shell blocked' } },
]);

console.log('Access rules configured: 5 rules');

// Step 3: Test evaluations
console.log('\n--- Policy Evaluation Tests ---\n');

const testActions = [
  { type: 'file_write', file: '/etc/passwd', operation: 'write' },
  { type: 'file_read', file: 'src/index.js', operation: 'read' },
  { type: 'command', command: 'git push --force origin main' },
  { type: 'command', command: 'npm install express' },
  { type: 'file_write', file: '.env.production', operation: 'write' },
];

for (const action of testActions) {
  let result;
  if (action.type === 'command') {
    result = checkCommandAccess(action.command);
  } else {
    result = checkFileAccess(action.file, action.operation);
  }

  const icon = result.allowed ? 'ALLOW' : 'BLOCK';
  const detail = action.command || `${action.operation} ${action.file}`;
  console.log(`  [${icon}] ${detail}`);
  if (!result.allowed) {
    console.log(`         Reason: ${result.reason}`);
  }

  // Log to audit trail
  await logAction({
    ...action,
    result: result.allowed ? 'allowed' : 'blocked',
    reason: result.reason,
    timestamp: new Date().toISOString()
  });
}

// Step 4: Data classification
console.log('\n--- Data Classification ---\n');
const testContent = 'My AWS key is AKIAIOSFODNN7EXAMPLE and password is secret123';
const classification = classifyContent(testContent);
console.log(`Sensitive data found: ${classification.hasSensitiveData}`);
classification.findings.forEach(f => {
  console.log(`  - ${f.type || f.pattern}: ${f.severity || 'detected'}`);
});

console.log('\nEnterprise setup complete.');
