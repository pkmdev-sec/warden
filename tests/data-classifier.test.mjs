import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  classifyContent,
  classifyFile,
  getSensitivePatterns,
  getSensitivePathPatterns,
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
});
