import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  addRule,
  checkFileAccess,
  checkCommandAccess,
  getRules,
  removeRule,
  clearRules,
  testGlobPattern,
  addRules,
} from '../lib/access-control.mjs';

describe('access-control', () => {
  beforeEach(() => {
    clearRules();
  });

  describe('addRule', () => {
    it('should add a file rule', () => {
      const rule = addRule('file', '/etc/**', 'block');
      assert.ok(rule.id);
      assert.equal(rule.type, 'file');
      assert.equal(rule.pattern, '/etc/**');
      assert.equal(rule.action, 'block');
    });

    it('should add a command rule', () => {
      const rule = addRule('command', 'rm\\s+-rf', 'block');
      assert.ok(rule.id);
      assert.equal(rule.type, 'command');
    });

    it('should reject invalid type', () => {
      assert.throws(() => addRule('invalid', '*', 'block'), /Invalid rule type/);
    });

    it('should reject invalid action', () => {
      assert.throws(() => addRule('file', '*', 'maybe'), /Invalid action/);
    });

    it('should support custom operations', () => {
      const rule = addRule('file', '*.log', 'allow', { operations: ['read'] });
      assert.deepEqual(rule.operations, ['read']);
    });

    it('should support description', () => {
      const rule = addRule('file', '*.secret', 'block', { description: 'Block secrets' });
      assert.equal(rule.description, 'Block secrets');
    });
  });

  describe('checkFileAccess', () => {
    it('should block matching file paths', () => {
      addRule('file', '/etc/**', 'block');
      const result = checkFileAccess('/etc/shadow', 'read');
      assert.equal(result.allowed, false);
      assert.ok(result.matchedRule);
    });

    it('should allow non-matching file paths (default allow)', () => {
      addRule('file', '/etc/**', 'block');
      const result = checkFileAccess('/home/user/code.js', 'read');
      assert.equal(result.allowed, true);
    });

    it('should handle glob patterns', () => {
      addRule('file', '**/*.env', 'block');
      const result = checkFileAccess('/app/config/.env', 'read');
      assert.equal(result.allowed, false);
    });

    it('should respect operation types', () => {
      addRule('file', '*.log', 'allow', { operations: ['read'] });
      addRule('file', '*.log', 'block', { operations: ['write', 'delete'] });
      const readResult = checkFileAccess('app.log', 'read');
      assert.equal(readResult.allowed, true);
      const writeResult = checkFileAccess('app.log', 'write');
      assert.equal(writeResult.allowed, false);
    });

    it('should use last-added rule priority', () => {
      addRule('file', '*.js', 'block');
      addRule('file', '*.js', 'allow');
      const result = checkFileAccess('app.js', 'read');
      assert.equal(result.allowed, true);
    });

    it('should return false for null path', () => {
      const result = checkFileAccess(null, 'read');
      assert.equal(result.allowed, false);
    });

    it('should return false for empty string', () => {
      const result = checkFileAccess('', 'read');
      assert.equal(result.allowed, false);
    });

    it('should match single-char wildcard ?', () => {
      addRule('file', '/tmp/?.txt', 'block');
      const result = checkFileAccess('/tmp/a.txt', 'read');
      assert.equal(result.allowed, false);
      const result2 = checkFileAccess('/tmp/ab.txt', 'read');
      assert.equal(result2.allowed, true); // ? matches one char
    });
  });

  describe('checkCommandAccess', () => {
    it('should block matching commands', () => {
      addRule('command', 'rm\\s+-rf', 'block');
      const result = checkCommandAccess('rm -rf /tmp');
      assert.equal(result.allowed, false);
    });

    it('should allow non-matching commands', () => {
      addRule('command', 'rm\\s+-rf', 'block');
      const result = checkCommandAccess('echo hello');
      assert.equal(result.allowed, true);
    });

    it('should support case-insensitive matching', () => {
      addRule('command', 'DROP TABLE', 'block');
      const result = checkCommandAccess('drop table users');
      assert.equal(result.allowed, false);
    });

    it('should return false for null command', () => {
      const result = checkCommandAccess(null);
      assert.equal(result.allowed, false);
    });

    it('should return false for empty command', () => {
      const result = checkCommandAccess('');
      assert.equal(result.allowed, false);
    });

    it('should handle complex regex patterns', () => {
      addRule('command', '^(sudo\\s+)?rm\\s+(-[a-z]+\\s+)*/', 'block');
      assert.equal(checkCommandAccess('rm -rf /').allowed, false);
      assert.equal(checkCommandAccess('sudo rm -rf /etc').allowed, false);
      assert.equal(checkCommandAccess('rm file.txt').allowed, true);
    });
  });

  describe('getRules', () => {
    it('should return file rules', () => {
      addRule('file', '*.js', 'allow');
      addRule('command', 'rm', 'block');
      const rules = getRules('file');
      assert.equal(rules.length, 1);
      assert.equal(rules[0].type, 'file');
    });

    it('should return command rules', () => {
      addRule('file', '*.js', 'allow');
      addRule('command', 'rm', 'block');
      const rules = getRules('command');
      assert.equal(rules.length, 1);
    });

    it('should return all rules when no type specified', () => {
      addRule('file', '*.js', 'allow');
      addRule('command', 'rm', 'block');
      const rules = getRules();
      assert.equal(rules.length, 2);
    });

    it('should not expose internal regex', () => {
      addRule('file', '*.js', 'allow');
      const rules = getRules();
      assert.ok(!('_regex' in rules[0]));
    });
  });

  describe('removeRule', () => {
    it('should remove an existing rule', () => {
      const rule = addRule('file', '*.js', 'block');
      assert.equal(getRules().length, 1);
      assert.ok(removeRule(rule.id));
      assert.equal(getRules().length, 0);
    });

    it('should return false for non-existent rule', () => {
      assert.ok(!removeRule('non-existent-id'));
    });
  });

  describe('clearRules', () => {
    it('should remove all rules', () => {
      addRule('file', '*.js', 'block');
      addRule('command', 'rm', 'block');
      clearRules();
      assert.equal(getRules().length, 0);
    });
  });

  describe('testGlobPattern - enhanced wildcards', () => {
    it('should match ** for deep directory traversal', () => {
      assert.ok(testGlobPattern('**/*.js', '/app/src/lib/util.js'));
      assert.ok(testGlobPattern('**/*.js', '/util.js'));
      assert.ok(testGlobPattern('/app/**/*.js', '/app/a/b/c/d.js'));
    });

    it('should match character classes [...]', () => {
      assert.ok(testGlobPattern('/tmp/[abc].txt', '/tmp/a.txt'));
      assert.ok(testGlobPattern('/tmp/[abc].txt', '/tmp/b.txt'));
      assert.ok(!testGlobPattern('/tmp/[abc].txt', '/tmp/d.txt'));
      assert.ok(testGlobPattern('/tmp/[a-z].txt', '/tmp/m.txt'));
    });

    it('should match negated character classes [!...]', () => {
      assert.ok(testGlobPattern('/tmp/[!0-9].txt', '/tmp/a.txt'));
      assert.ok(!testGlobPattern('/tmp/[!0-9].txt', '/tmp/5.txt'));
    });

    it('should match brace expansion {a,b,c}', () => {
      assert.ok(testGlobPattern('/app/*.{js,ts}', '/app/index.js'));
      assert.ok(testGlobPattern('/app/*.{js,ts}', '/app/index.ts'));
      assert.ok(!testGlobPattern('/app/*.{js,ts}', '/app/index.py'));
    });

    it('should handle brace expansion with wildcards', () => {
      assert.ok(testGlobPattern('/app/{src,lib}/*.js', '/app/src/util.js'));
      assert.ok(testGlobPattern('/app/{src,lib}/*.js', '/app/lib/main.js'));
      assert.ok(!testGlobPattern('/app/{src,lib}/*.js', '/app/test/spec.js'));
    });

    it('should match ? for single character', () => {
      assert.ok(testGlobPattern('/tmp/?.log', '/tmp/a.log'));
      assert.ok(!testGlobPattern('/tmp/?.log', '/tmp/ab.log'));
      assert.ok(testGlobPattern('/tmp/test-?.log', '/tmp/test-1.log'));
    });

    it('should handle edge cases with special characters', () => {
      assert.ok(testGlobPattern('/app/*.js', '/app/index.js'));
      assert.ok(testGlobPattern('/app/**', '/app/a/b/c/d/e'));
      assert.ok(!testGlobPattern('/app/*', '/app/a/b'));
    });

    it('should handle empty or malformed patterns gracefully', () => {
      assert.ok(!testGlobPattern('', '/any/path'));
      assert.ok(!testGlobPattern(null, '/any/path'));
    });
  });

  describe('addRule - useRegex option', () => {
    it('should support direct regex patterns when useRegex is true', () => {
      addRule('file', '^/tmp/.*\\.log$', 'block', { useRegex: true });
      const result = checkFileAccess('/tmp/app.log', 'read');
      assert.equal(result.allowed, false);
    });

    it('should use glob by default when useRegex is false', () => {
      addRule('file', '/tmp/*.log', 'block', { useRegex: false });
      const result = checkFileAccess('/tmp/app.log', 'read');
      assert.equal(result.allowed, false);
    });

    it('should handle complex regex with useRegex', () => {
      addRule('file', '^/(etc|var)/(?!public).*', 'block', { useRegex: true });
      assert.equal(checkFileAccess('/etc/shadow', 'read').allowed, false);
      assert.equal(checkFileAccess('/var/log/system', 'read').allowed, false);
      assert.equal(checkFileAccess('/var/public/data', 'read').allowed, true);
    });
  });

  describe('addRules - bulk add', () => {
    it('should add multiple rules at once', () => {
      const rules = addRules([
        { type: 'file', pattern: '*.env', action: 'block' },
        { type: 'file', pattern: '*.key', action: 'block' },
        { type: 'command', pattern: 'rm.*-rf', action: 'block' },
      ]);

      assert.equal(rules.length, 3);
      assert.equal(getRules().length, 3);
    });

    it('should handle partial failures gracefully', () => {
      const rules = addRules([
        { type: 'file', pattern: '*.js', action: 'allow' },
        { type: 'invalid', pattern: '*.txt', action: 'block' }, // Invalid
        { type: 'file', pattern: '*.py', action: 'block' },
      ]);

      assert.equal(rules.length, 2); // Only valid rules added
      assert.equal(getRules().length, 2);
    });

    it('should throw on invalid input type', () => {
      assert.throws(() => addRules('not an array'), /must be an array/);
    });

    it('should handle empty array', () => {
      const rules = addRules([]);
      assert.equal(rules.length, 0);
    });
  });

  describe('glob edge cases', () => {
    it('should handle paths with dots correctly', () => {
      addRule('file', '**/.env*', 'block');
      assert.equal(checkFileAccess('/app/.env', 'read').allowed, false);
      assert.equal(checkFileAccess('/app/.env.local', 'read').allowed, false);
      assert.equal(checkFileAccess('/app/config.js', 'read').allowed, true);
    });

    it('should match extensions correctly', () => {
      addRule('file', '**/*.{js,ts,jsx,tsx}', 'allow');
      assert.equal(checkFileAccess('/src/app.jsx', 'read').allowed, true);
      assert.equal(checkFileAccess('/src/app.tsx', 'read').allowed, true);
    });

    it('should handle trailing slashes in directory patterns', () => {
      addRule('file', '/tmp/**', 'block');
      assert.equal(checkFileAccess('/tmp/file.txt', 'read').allowed, false);
      assert.equal(checkFileAccess('/tmp/a/b/c', 'read').allowed, false);
    });
  });
});
