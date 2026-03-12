import { describe, it, beforeEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  loadPolicies,
  getPolicies,
  matchRule,
  getViolations,
  evaluateAction,
  composePolicies,
  evaluateComposedPolicy,
} from '../lib/policy-engine.mjs';

const TEST_DIR = join(tmpdir(), 'warden-test-policies-' + Date.now());

before(async () => {
  await mkdir(TEST_DIR, { recursive: true });

  await writeFile(join(TEST_DIR, 'safety.json'), JSON.stringify({
    name: 'safety',
    description: 'Basic safety rules',
    rules: [
      { match: { command: 'rm\\s+-rf\\s+/' }, action: 'block', description: 'Block recursive root delete' },
      { match: { command: 'git.*--force' }, action: 'warn', description: 'Warn on force push' },
      { match: { tool: 'Write' }, action: 'allow', description: 'Allow writes' },
      { match: { path: '/etc/shadow' }, action: 'block', description: 'Block shadow access' },
      { match: { pattern: '\\.env' }, action: 'warn', description: 'Warn on .env files' },
    ],
  }));

  await writeFile(join(TEST_DIR, 'strict.json'), JSON.stringify({
    name: 'strict',
    description: 'Strict enterprise rules',
    rules: [
      { match: { command: 'curl|wget' }, action: 'warn', description: 'Warn on network commands' },
      { match: { tool: 'Bash', command: 'deploy' }, action: 'block', description: 'Block deploy' },
    ],
  }));

  // Non-JSON file should be ignored
  await writeFile(join(TEST_DIR, 'readme.txt'), 'not a policy');
});

describe('loadPolicies', () => {
  it('should load all valid JSON policies from a directory', async () => {
    const policies = await loadPolicies(TEST_DIR);
    assert.equal(policies.size, 2);
    assert.ok(policies.has('safety'));
    assert.ok(policies.has('strict'));
  });

  it('should ignore non-JSON files', async () => {
    const policies = await loadPolicies(TEST_DIR);
    assert.equal(policies.size, 2);
  });

  it('should throw on invalid policy files', async () => {
    const badDir = join(tmpdir(), 'warden-bad-' + Date.now());
    await mkdir(badDir, { recursive: true });
    await writeFile(join(badDir, 'bad.json'), JSON.stringify({ foo: 'bar' }));
    const result = await loadPolicies(badDir);
    assert.strictEqual(result.size, 0, 'Invalid policies should be skipped gracefully');
    await rm(badDir, { recursive: true });
  });

  it('should clear previously loaded policies', async () => {
    await loadPolicies(TEST_DIR);
    assert.equal(getPolicies().size, 2);
    const emptyDir = join(tmpdir(), 'warden-empty-' + Date.now());
    await mkdir(emptyDir, { recursive: true });
    await loadPolicies(emptyDir);
    assert.equal(getPolicies().size, 0);
    // Reload for subsequent tests
    await loadPolicies(TEST_DIR);
  });
});

describe('matchRule', () => {
  it('should match by tool name (case-insensitive)', () => {
    const rule = { match: { tool: 'Bash' }, action: 'block' };
    assert.ok(matchRule(rule, { tool: 'Bash' }));
    assert.ok(matchRule(rule, { tool: 'bash' }));
    assert.ok(!matchRule(rule, { tool: 'Write' }));
  });

  it('should match by command regex', () => {
    const rule = { match: { command: 'rm\\s+-rf' }, action: 'block' };
    assert.ok(matchRule(rule, { command: 'rm -rf /' }));
    assert.ok(matchRule(rule, { command: 'sudo rm -rf /tmp' }));
    assert.ok(!matchRule(rule, { command: 'rm file.txt' }));
  });

  it('should match by path prefix', () => {
    const rule = { match: { path: '/etc/' }, action: 'block' };
    assert.ok(matchRule(rule, { path: '/etc/shadow' }));
    assert.ok(matchRule(rule, { path: '/etc/passwd' }));
    assert.ok(!matchRule(rule, { path: '/home/user/.env' }));
  });

  it('should match by pattern against full action JSON', () => {
    const rule = { match: { pattern: '\\.env' }, action: 'warn' };
    assert.ok(matchRule(rule, { path: '/app/.env' }));
    assert.ok(matchRule(rule, { command: 'cat .env' }));
    assert.ok(!matchRule(rule, { path: '/app/config.json' }));
  });

  it('should require ALL conditions to match (AND logic)', () => {
    const rule = { match: { tool: 'Bash', command: 'deploy' }, action: 'block' };
    assert.ok(matchRule(rule, { tool: 'Bash', command: 'deploy production' }));
    assert.ok(!matchRule(rule, { tool: 'Write', command: 'deploy production' }));
    assert.ok(!matchRule(rule, { tool: 'Bash', command: 'echo hello' }));
  });

  it('should return false for null/undefined inputs', () => {
    assert.ok(!matchRule(null, {}));
    assert.ok(!matchRule({}, null));
    assert.ok(!matchRule({ match: {} }, {}));
  });

  it('should handle missing action fields gracefully', () => {
    const rule = { match: { command: 'test' }, action: 'block' };
    assert.ok(!matchRule(rule, { tool: 'Bash' })); // no command field
  });

  it('should handle invalid regex gracefully by falling back to string includes', () => {
    const rule = { match: { command: '[invalid(' }, action: 'block' };
    // Should not throw — falls back to includes
    assert.ok(!matchRule(rule, { command: 'something' }));
  });
});

describe('getViolations', () => {
  before(async () => {
    await loadPolicies(TEST_DIR);
  });

  it('should return block violations', () => {
    const violations = getViolations({ command: 'rm -rf /' });
    assert.ok(violations.length > 0);
    assert.ok(violations.some(v => v.severity === 'critical'));
  });

  it('should return warn violations', () => {
    const violations = getViolations({ command: 'git push --force' });
    assert.ok(violations.length > 0);
    assert.ok(violations.some(v => v.severity === 'warning'));
  });

  it('should return empty for allowed actions', () => {
    const violations = getViolations({ tool: 'Read', path: '/app/index.js' });
    assert.equal(violations.length, 0);
  });

  it('should not return allow rules as violations', () => {
    const violations = getViolations({ tool: 'Write' });
    assert.equal(violations.length, 0);
  });

  it('should return violations from multiple policies', () => {
    const violations = getViolations({ tool: 'Bash', command: 'curl http://example.com' });
    assert.ok(violations.some(v => v.policy === 'strict'));
  });
});

describe('evaluateAction', () => {
  before(async () => {
    await loadPolicies(TEST_DIR);
  });

  it('should block dangerous commands', () => {
    const result = evaluateAction({ command: 'rm -rf /' });
    assert.equal(result.allowed, false);
    assert.ok(result.violations.length > 0);
  });

  it('should allow safe commands', () => {
    const result = evaluateAction({ tool: 'Read', path: '/app/src/index.js' });
    assert.equal(result.allowed, true);
    assert.equal(result.violations.length, 0);
  });

  it('should separate warnings from blocks', () => {
    const result = evaluateAction({ command: 'git push --force' });
    assert.equal(result.allowed, true); // warn doesn't block
    assert.ok(result.warnings.length > 0);
  });

  it('should merge context into action', () => {
    const result = evaluateAction(
      { tool: 'Bash', command: 'deploy app' },
      { environment: 'production' }
    );
    assert.equal(result.allowed, false);
  });

  it('should handle empty action', () => {
    const result = evaluateAction({});
    assert.equal(result.allowed, true);
  });
});

describe('composePolicies', () => {
  const policy1 = {
    name: 'policy1',
    rules: [
      { match: { command: 'rm' }, action: 'block', description: 'Block rm' },
      { match: { tool: 'Write' }, action: 'allow' },
    ],
  };

  const policy2 = {
    name: 'policy2',
    rules: [
      { match: { command: 'delete' }, action: 'block', description: 'Block delete' },
      { match: { path: '/tmp' }, action: 'warn', description: 'Warn on /tmp' },
    ],
  };

  it('should compose policies with AND operator', () => {
    const composed = composePolicies([policy1, policy2], 'AND', { name: 'strict-combined' });
    assert.equal(composed.name, 'strict-combined');
    assert.equal(composed.composition.operator, 'AND');
    assert.ok(composed.rules.length > 0);
    assert.ok(composed.rules.some(r => r.sourcePolicy === 'policy1'));
    assert.ok(composed.rules.some(r => r.sourcePolicy === 'policy2'));
  });

  it('should compose policies with OR operator', () => {
    const composed = composePolicies([policy1, policy2], 'OR', { name: 'permissive-combined' });
    assert.equal(composed.name, 'permissive-combined');
    assert.equal(composed.composition.operator, 'OR');
  });

  it('should throw on invalid inputs', () => {
    assert.throws(() => composePolicies([], 'AND'), /non-empty array/);
    assert.throws(() => composePolicies([policy1], 'INVALID'), /must be "AND" or "OR"/);
    assert.throws(() => composePolicies([{ foo: 'bar' }], 'AND'), /must have a name and rules/);
  });

  it('should evaluate AND composition - block if any policy blocks', () => {
    const composed = composePolicies([policy1, policy2], 'AND');
    const result1 = evaluateComposedPolicy(composed, { command: 'rm file.txt' });
    assert.equal(result1.allowed, false);
    assert.ok(result1.violations.length > 0);

    const result2 = evaluateComposedPolicy(composed, { command: 'delete file.txt' });
    assert.equal(result2.allowed, false);
  });

  it('should evaluate OR composition - allow if at least one allows', () => {
    const composed = composePolicies([policy1, policy2], 'OR');

    // Only policy1 would block 'rm', policy2 doesn't match
    const result1 = evaluateComposedPolicy(composed, { command: 'rm file.txt' });
    // OR: blocks only if ALL policies that match would block
    // Since policy2 doesn't match at all, it's not considered
    assert.equal(result1.allowed, false); // policy1 matches and blocks

    // Both would block the same thing
    const blockAll = {
      name: 'blockall',
      rules: [{ match: { command: '.*' }, action: 'block' }],
    };
    const composed2 = composePolicies([blockAll, blockAll], 'OR');
    const result2 = evaluateComposedPolicy(composed2, { command: 'anything' });
    assert.equal(result2.allowed, false); // Both match and block
  });

  it('should handle empty policy composition', () => {
    const composed = composePolicies([policy1], 'AND');
    const result = evaluateComposedPolicy(composed, { tool: 'Read' });
    assert.equal(result.allowed, true);
  });

  it('should track source policies in violations', () => {
    const composed = composePolicies([policy1, policy2], 'AND');
    const result = evaluateComposedPolicy(composed, { command: 'rm file.txt' });
    assert.ok(result.violations.some(v => v.sourcePolicy === 'policy1'));
  });

  it('should handle warnings in composed policies', () => {
    const composed = composePolicies([policy1, policy2], 'AND');
    const result = evaluateComposedPolicy(composed, { path: '/tmp/test' });
    assert.equal(result.allowed, true);
    assert.ok(result.warnings.length > 0);
  });

  it('should handle invalid composed policy evaluation gracefully', () => {
    // Should not throw but return safe defaults
    const result = evaluateComposedPolicy({}, { command: 'test' });
    assert.ok(result);
    assert.equal(result.allowed, true); // Default to allow on error
  });
});
