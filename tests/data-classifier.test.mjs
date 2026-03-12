import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  classifyContent,
  classifyFile,
  getSensitivePatterns,
  getSensitivePathPatterns,
  addCustomRule,
  removeCustomRule,
  getCustomRules,
  clearCustomRules,
  classifyContentExtended,
  getMLConfig,
} from '../lib/data-classifier.mjs';

describe('data-classifier', { concurrency: false }, () => {
  describe('classifyContent', { concurrency: false }, () => {
    it('should detect AWS access keys', () => {
      const result = classifyContent('My key is AKIAIOSFODNN7EXAMPLE');
      assert.ok(result.hasSensitiveData, 'Expected hasSensitiveData to be true');
      assert.ok(result.findings.some(f => f.name === 'AWS Access Key'));
    });

    it('should detect generic API keys', () => {
      const result = classifyContent('api_key = "sk_test_' + '0'.repeat(24) + '"');
      assert.ok(result.hasSensitiveData);
      assert.ok(result.findings.some(f => f.name === 'Generic API Key'));
    });

    it('should detect Bearer tokens', () => {
      const result = classifyContent('Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def');
      assert.ok(result.hasSensitiveData);
      assert.ok(result.findings.some(f => f.name === 'Bearer Token'));
    });

    it('should detect private keys', () => {
      const result = classifyContent('-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...');
      assert.ok(result.hasSensitiveData);
      assert.ok(result.findings.some(f => f.name === 'Private Key'));
    });

    it('should detect GitHub tokens', () => {
      const result = classifyContent('token: ghp_1234567890abcdefghijklmnopqrstuvwxyz');
      assert.ok(result.hasSensitiveData);
      assert.ok(result.findings.some(f => f.name === 'GitHub Token'));
    });

    it('should detect password assignments', () => {
      const result = classifyContent('password = "SuperSecret123!"');
      assert.ok(result.hasSensitiveData);
      assert.ok(result.findings.some(f => f.name === 'Password Assignment'));
    });

    it('should detect SSNs', () => {
      const result = classifyContent('SSN: 123-45-6789');
      assert.ok(result.hasSensitiveData);
      assert.ok(result.findings.some(f => f.name === 'SSN'));
    });

    it('should detect email addresses', () => {
      const result = classifyContent('Contact: user@example.com');
      assert.ok(result.hasSensitiveData);
      assert.ok(result.findings.some(f => f.name === 'Email Address'));
    });

    it('should detect credit card numbers', () => {
      const result = classifyContent('Card: 4111111111111111');
      assert.ok(result.hasSensitiveData);
      assert.ok(result.findings.some(f => f.name === 'Credit Card'));
    });

    it('should detect database connection strings', () => {
      const result = classifyContent('DATABASE_URL=postgres://user:pass@host:5432/db');
      assert.ok(result.hasSensitiveData);
      assert.ok(result.findings.some(f => f.name === 'Database Connection String'));
    });

    it('should return summary with categories', () => {
      const result = classifyContent('key: AKIAIOSFODNN7EXAMPLE email: test@test.com SSN: 123-45-6789');
      assert.ok(result.summary.credential > 0);
      assert.ok(result.summary.pii > 0);
    });

    it('should handle empty/null input', () => {
      assert.equal(classifyContent('').hasSensitiveData, false);
      assert.equal(classifyContent(null).hasSensitiveData, false);
      assert.equal(classifyContent(undefined).hasSensitiveData, false);
    });

    it('should handle clean content with no sensitive data', () => {
      const result = classifyContent('function add(a, b) { return a + b; }');
      assert.equal(result.hasSensitiveData, false);
      assert.equal(result.findings.length, 0);
    });

    it('should mask sensitive data in samples', () => {
      const result = classifyContent('My key AKIAIOSFODNN7EXAMPLE here');
      assert.ok(result.hasSensitiveData, 'Expected sensitive data detected');
      const finding = result.findings.find(f => f.name === 'AWS Access Key');
      assert.ok(finding, 'Expected AWS Access Key finding');
      assert.ok(finding.samples[0].includes('***'));
    });

    it('should count multiple occurrences', () => {
      const result = classifyContent('SSN: 123-45-6789 and also 987-65-4321');
      assert.ok(result.hasSensitiveData, 'Expected sensitive data detected');
      const finding = result.findings.find(f => f.name === 'SSN');
      assert.ok(finding, 'Expected SSN finding');
      assert.equal(finding.count, 2);
    });
  });

  describe('classifyFile', { concurrency: false }, () => {
    it('should flag .env files by path', async () => {
      const tmpFile = join(tmpdir(), '.env');
      await writeFile(tmpFile, 'DB_PASSWORD=secret123', 'utf-8');
      const result = await classifyFile(tmpFile);
      assert.ok(result.hasSensitiveData);
      assert.ok(result.pathFindings.some(f => f.name === 'Environment file'));
      await rm(tmpFile);
    });

    it('should flag .pem files by path', async () => {
      const result = await classifyFile('/certs/server.pem');
      assert.ok(result.pathFindings.some(f => f.name === 'PEM certificate'));
    });

    it('should flag .key files by path', async () => {
      const result = await classifyFile('/certs/private.key');
      assert.ok(result.pathFindings.some(f => f.name === 'Key file'));
    });

    it('should scan file content for sensitive data', async () => {
      const tmpFile = join(tmpdir(), `test-scan-${Date.now()}.txt`);
      await writeFile(tmpFile, 'API_KEY=AKIAIOSFODNN7EXAMPLE\npassword="admin123!"', 'utf-8');
      const result = await classifyFile(tmpFile);
      assert.ok(result.contentFindings.length > 0);
      await rm(tmpFile);
    });

    it('should determine overall severity', async () => {
      const tmpFile = join(tmpdir(), `test-sev-${Date.now()}.env`);
      await writeFile(tmpFile, 'SSN=123-45-6789', 'utf-8');
      const result = await classifyFile(tmpFile);
      assert.equal(result.overallSeverity, 'critical');
      await rm(tmpFile);
    });

    it('should handle non-existent files gracefully', async () => {
      const result = await classifyFile('/non/existent/file.txt');
      assert.equal(result.contentFindings.length, 0);
    });

    it('should return clean result for safe files', async () => {
      const tmpFile = join(tmpdir(), `safe-${Date.now()}.js`);
      await writeFile(tmpFile, 'const x = 42;', 'utf-8');
      const result = await classifyFile(tmpFile);
      assert.equal(result.hasSensitiveData, false);
      assert.equal(result.overallSeverity, 'none');
      await rm(tmpFile);
    });
  });

  describe('getSensitivePatterns', () => {
    it('should return all patterns', () => {
      const patterns = getSensitivePatterns();
      assert.ok(Array.isArray(patterns));
      assert.ok(patterns.length > 10);
    });

    it('should include name, category, severity, and regex', () => {
      const patterns = getSensitivePatterns();
      for (const p of patterns) {
        assert.ok(p.name);
        assert.ok(p.category);
        assert.ok(p.severity);
        assert.ok(p.regex);
      }
    });
  });

  describe('getSensitivePathPatterns', () => {
    it('should return path patterns', () => {
      const patterns = getSensitivePathPatterns();
      assert.ok(Array.isArray(patterns));
      assert.ok(patterns.length > 5);
    });

    it('should include pattern as string source', () => {
      const patterns = getSensitivePathPatterns();
      for (const p of patterns) {
        assert.ok(p.name);
        assert.ok(p.pattern);
      }
    });
  });

  describe('addCustomRule', () => {
    beforeEach(() => {
      clearCustomRules();
    });

    it('should add a custom classification rule', () => {
      const rule = addCustomRule({
        name: 'Employee ID',
        regex: /EMP-\d{6}/g,
        category: 'pii',
        severity: 'medium',
        description: 'Employee identifier',
      });

      assert.ok(rule);
      assert.equal(rule.name, 'Employee ID');
      assert.equal(rule.category, 'pii');
      assert.equal(rule.severity, 'medium');
      assert.ok(rule.custom);
    });

    it('should convert string regex to RegExp', () => {
      const rule = addCustomRule({
        name: 'Test Pattern',
        regex: 'TEST-\\d+',
        category: 'custom',
        severity: 'low',
      });

      assert.ok(rule);
      assert.ok(rule.regex instanceof RegExp);
    });

    it('should throw on missing name', () => {
      assert.throws(
        () => addCustomRule({ regex: /test/g, category: 'pii', severity: 'low' }),
        /must have a name/
      );
    });

    it('should throw on missing regex', () => {
      assert.throws(
        () => addCustomRule({ name: 'Test', category: 'pii', severity: 'low' }),
        /must have a regex/
      );
    });

    it('should throw on invalid severity', () => {
      assert.throws(
        () => addCustomRule({ name: 'Test', regex: /test/g, category: 'pii', severity: 'extreme' }),
        /valid severity/
      );
    });

    it('should throw on invalid regex string', () => {
      assert.throws(
        () => addCustomRule({ name: 'Test', regex: '[invalid(', category: 'pii', severity: 'low' }),
        /Invalid regex pattern/
      );
    });

    it('should ensure global flag on regex', () => {
      const rule = addCustomRule({
        name: 'Test',
        regex: /TEST/i,
        category: 'test',
        severity: 'low',
      });

      assert.ok(rule.regex.flags.includes('g'));
    });
  });

  describe('removeCustomRule', () => {
    beforeEach(() => {
      clearCustomRules();
    });

    it('should remove an existing custom rule', () => {
      addCustomRule({ name: 'Test1', regex: /test/g, category: 'test', severity: 'low' });
      assert.equal(getCustomRules().length, 1);

      const removed = removeCustomRule('Test1');
      assert.ok(removed);
      assert.equal(getCustomRules().length, 0);
    });

    it('should return false for non-existent rule', () => {
      const removed = removeCustomRule('NonExistent');
      assert.equal(removed, false);
    });
  });

  describe('getCustomRules', () => {
    beforeEach(() => {
      clearCustomRules();
    });

    it('should return all custom rules', () => {
      addCustomRule({ name: 'Test1', regex: /test1/g, category: 'test', severity: 'low' });
      addCustomRule({ name: 'Test2', regex: /test2/g, category: 'test', severity: 'high' });

      const rules = getCustomRules();
      assert.equal(rules.length, 2);
      assert.ok(rules.some(r => r.name === 'Test1'));
      assert.ok(rules.some(r => r.name === 'Test2'));
    });

    it('should include regex as source string', () => {
      addCustomRule({ name: 'Test', regex: /pattern/g, category: 'test', severity: 'low' });
      const rules = getCustomRules();
      assert.equal(rules[0].regex, 'pattern');
    });
  });

  describe('clearCustomRules', () => {
    beforeEach(() => {
      clearCustomRules();
    });

    it('should remove all custom rules', () => {
      addCustomRule({ name: 'Test1', regex: /test1/g, category: 'test', severity: 'low' });
      addCustomRule({ name: 'Test2', regex: /test2/g, category: 'test', severity: 'low' });
      assert.ok(getCustomRules().length >= 2);

      clearCustomRules();
      assert.equal(getCustomRules().length, 0);
    });
  });

  describe('classifyContentExtended', () => {
    beforeEach(() => {
      clearCustomRules();
    });

    it('should include built-in and custom patterns', () => {
      addCustomRule({
        name: 'Company ID',
        regex: /COMP-\d{4}/g,
        category: 'pii',
        severity: 'medium',
      });

      const result = classifyContentExtended('COMP-1234 and SSN: 123-45-6789');
      assert.ok(result.hasSensitiveData);
      assert.ok(result.findings.some(f => f.name === 'Company ID' && f.custom));
      assert.ok(result.findings.some(f => f.name === 'SSN'));
    });

    it('should skip custom patterns when includeCustom is false', () => {
      addCustomRule({
        name: 'Custom',
        regex: /CUSTOM-\d+/g,
        category: 'test',
        severity: 'low',
      });

      const result = classifyContentExtended('CUSTOM-123', { includeCustom: false });
      assert.ok(!result.findings.some(f => f.custom));
    });

    it('should use ML detection when useML is true', () => {
      const result = classifyContentExtended('John Smith lives at 123 Main Street', { useML: true });
      assert.ok(result.findings.some(f => f.ml));
    });

    it('should handle empty content', () => {
      const result = classifyContentExtended('');
      assert.equal(result.hasSensitiveData, false);
    });

    it('should update summary with custom findings', () => {
      addCustomRule({
        name: 'Custom PII',
        regex: /CUSTOM-\d+/g,
        category: 'custom_category',
        severity: 'high',
      });

      const result = classifyContentExtended('CUSTOM-123 and CUSTOM-456');
      assert.equal(result.summary.custom_category, 2);
    });
  });

  describe('ML detection', () => {
    it('should detect potential names', () => {
      const result = classifyContentExtended('Contact John Smith for details', { useML: true });
      const nameFindings = result.findings.filter(f => f.name === 'Potential Name (ML)');
      assert.ok(nameFindings.length > 0);
      assert.ok(nameFindings[0].confidence);
    });

    it('should detect potential addresses', () => {
      const result = classifyContentExtended('Address: 123 Main Street', { useML: true });
      const addrFindings = result.findings.filter(f => f.name === 'Potential Address (ML)');
      assert.ok(addrFindings.length > 0);
    });

    it('should detect sensitive context keywords', () => {
      const result = classifyContentExtended('confidential report internal data', { useML: true });
      const contextFindings = result.findings.filter(f => f.name === 'Sensitive Context (ML)');
      assert.ok(contextFindings.length > 0);
    });

    it('should filter out day/month names from name detection', () => {
      const result = classifyContentExtended('Monday January meeting', { useML: true });
      const nameFindings = result.findings.filter(f => f.name === 'Potential Name (ML)');
      assert.equal(nameFindings.length, 0);
    });

    it('should mark ML findings with ml flag', () => {
      const result = classifyContentExtended('123 Oak Avenue', { useML: true });
      const mlFindings = result.findings.filter(f => f.ml);
      assert.ok(mlFindings.length > 0);
      assert.ok(mlFindings[0].confidence);
    });
  });

  describe('getMLConfig', () => {
    it('should return ML configuration', () => {
      const config = getMLConfig();
      assert.ok(config);
      assert.equal(config.available, true);
      assert.ok(Array.isArray(config.capabilities));
      assert.ok(config.capabilities.length > 0);
    });

    it('should indicate heuristic-stub type', () => {
      const config = getMLConfig();
      assert.equal(config.type, 'heuristic-stub');
    });
  });
});
