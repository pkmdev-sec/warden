![Warden Banner](assets/banner.svg)

# WARDEN

**Enterprise Policy Enforcement for Claude Code**

Warden is a governance and compliance framework that enforces organizational policies on AI-assisted development. It provides real-time access control, data classification, audit logging, and compliance reporting — ensuring that Claude Code operates within your enterprise security boundaries.

## Why Warden?

From Old English *weardian*, meaning **guardian** or **keeper**. A warden is the sentinel entrusted with protecting what matters most — the keeper of gates, the guardian of standards, the enforcer of rules.

In medieval governance, the Warden held authority over a territory's security, ensuring that laws were upheld and boundaries respected. WARDEN applies this ancient role to modern AI governance — an intelligent guardian that monitors every Claude Code interaction against your organization's policies, ensuring compliance without impeding productivity.

Where other tools react to violations after they occur, Warden **prevents** them — standing watch at every gate, enforcing every policy, logging every action.

## Features

- **Policy Engine** — Define and enforce custom rules with JSON-based policy definitions
- **Access Control** — Role-based permissions with operation-level granularity
- **Data Classifier** — Automatic detection and handling of sensitive data patterns
- **Audit Logger** — Immutable, structured logging of all policy decisions
- **Compliance Reporter** — Generate compliance reports with violation summaries

## Quick Start

```javascript
import { loadPolicies, evaluateAction, matchRule } from './lib/policy-engine.mjs';
import { checkAccess } from './lib/access-control.mjs';
import { classifyContent } from './lib/data-classifier.mjs';

// Load policies from directory
await loadPolicies('./policies');

// Evaluate an action against all loaded policies
const result = evaluateAction({
  tool: 'Write',
  command: 'write',
  path: '/src/auth.js',
  user: 'developer'
});

// Check if action is allowed
if (!result.allowed) {
  console.error('Action blocked:', result.violations);
}

// Check access before operations
const access = checkAccess('developer', 'file:write', '/src/auth.js');

// Classify sensitive data
const classification = classifyContent(content);
```

## Examples

The `examples/` directory contains practical, working examples demonstrating Warden's capabilities:

### [basic-policy.json](examples/basic-policy.json)
A starter policy template showing common patterns:
- Blocking production database access
- Preventing force pushes to main branch
- Warning on .env file access
- Protecting credential/secret files
- Monitoring dependency changes

Use this as a template for creating your own custom policies.

### [enterprise-setup.mjs](examples/enterprise-setup.mjs)
Complete enterprise configuration demonstrating:
- Loading multiple policy layers
- Composing policies with AND/OR logic
- Setting up comprehensive access control rules
- Testing policy evaluations
- Data classification and audit logging

Run with: `node examples/enterprise-setup.mjs`

### [audit-query.mjs](examples/audit-query.mjs)
Query and analyze audit logs:
- Logging sample actions
- Querying blocked actions
- Generating audit statistics
- Creating compliance reports
- Exporting CSV data for external auditors

Run with: `node examples/audit-query.mjs`

## Architecture

See [Architecture Diagram](docs/visuals/architecture-diagram.svg) for system overview.

## Modules

| Module | Purpose |
|--------|---------|
| `policy-engine` | Core rule evaluation and enforcement |
| `access-control` | Role-based permission checks |
| `data-classifier` | Sensitive data pattern detection |
| `audit-logger` | Immutable structured audit trail |
| `compliance-reporter` | Compliance summaries and reports |

## Policy Testing (Dry-Run)

Warden includes a dry-run mode that lets you test policies without actually blocking actions. This is invaluable for:
- Testing new policies before deployment
- Understanding policy behavior
- Debugging rule matching logic
- Training and documentation

### Dry-Run Mode

Test what would happen without actually blocking:

```javascript
import { dryRun } from './lib/policy-engine.mjs';

const result = dryRun({
  tool: 'Write',
  path: '/etc/passwd',
  command: 'write'
});

console.log(result.summary);
// Output: "WOULD BLOCK: Direct system file access prohibited"

console.log(result.wouldBlock); // true
console.log(result.wouldWarn);  // false
```

### Test Policy Files

Test a specific policy file against multiple actions:

```javascript
import { testPolicy } from './lib/policy-engine.mjs';

const testActions = [
  { tool: 'Write', path: '/secrets/api-keys.json' },
  { tool: 'Bash', command: 'git push --force origin main' },
  { tool: 'Read', path: '/src/index.js' },
];

const results = await testPolicy('./policies/default.json', testActions);

results.forEach(r => {
  console.log(`${r.action.tool}: ${r.summary}`);
});
```

Output:
```
Write: WOULD BLOCK: Access to secrets directory prohibited
Bash: WOULD BLOCK: Force push to main branch not allowed
Read: WOULD ALLOW: No policy violations
```

## Audit Log Search

Warden provides powerful search capabilities for audit logs, enabling quick investigation of security incidents and compliance queries.

### Search by Text

Search all log entries for specific terms:

```javascript
import { searchLog } from './lib/audit-logger.mjs';

// Find all entries mentioning "production"
const results = await searchLog('production', { limit: 100 });

// Case-sensitive search
const sensitiveResults = await searchLog('SECRET', {
  caseSensitive: true,
  limit: 50
});

console.log(`Found ${results.length} matching entries`);
```

### Query with Filters

Filter logs by specific attributes:

```javascript
import { queryLog } from './lib/audit-logger.mjs';

// Get all blocked actions
const blocked = await queryLog({ result: 'blocked' });

// Get all Bash commands by a specific user
const userCommands = await queryLog({
  user: 'john.doe',
  tool: 'Bash'
});

// Get actions within a time range
const recentActions = await queryLog({
  startDate: '2026-03-01T00:00:00Z',
  endDate: '2026-03-12T23:59:59Z'
});
```

### Generate Reports

Create compliance reports for auditors:

```javascript
import { generateReport, getStats } from './lib/audit-logger.mjs';
import { generateSOC2Report, exportCSV } from './lib/compliance-reporter.mjs';

const period = {
  startDate: '2026-03-01T00:00:00Z',
  endDate: '2026-03-12T23:59:59Z'
};

// Executive summary
const report = await generateReport(period);

// SOC2 compliance report
const soc2 = await generateSOC2Report(period);

// Export as CSV for external auditors
const csv = await exportCSV(period);
await writeFile('audit-export.csv', csv);
```

## Policy Format

Policies are defined as JSON files in the `policies/` directory. Each policy file must follow this schema:

### Schema

```json
{
  "name": "string (required)",
  "description": "string (optional)",
  "version": "string (optional)",
  "rules": [
    {
      "id": "string (optional)",
      "description": "string (optional)",
      "match": {
        "tool": "string (optional) - Tool name (Read, Write, Edit, Bash, etc.)",
        "command": "string (optional) - Regex pattern for command matching",
        "path": "string (optional) - Glob pattern for file path matching",
        "pattern": "string (optional) - Regex pattern against entire action JSON",
        "file": "string (optional) - Alias for path",
        "operation": "string (optional) - read/write/delete"
      },
      "action": "string (required) - 'allow', 'block', or 'warn'",
      "message": "string (optional) - Custom message shown on violation"
    }
  ]
}
```

### Pattern Matching

**Tool Matching:** Case-insensitive exact match
```json
{ "match": { "tool": "Bash" } }
```

**Command Matching:** Regex pattern or substring
```json
{ "match": { "command": "git push.*--force" } }
{ "match": { "command": "*production*" } }
```

**Path Matching:** Glob patterns with wildcards
```json
{ "match": { "path": "/etc/**" } }           // Any file under /etc/
{ "match": { "path": "**/.env*" } }          // Any .env file anywhere
{ "match": { "path": "**/*.{pem,key}" } }    // Certificate and key files
```

**Pattern Matching:** Regex against full action JSON
```json
{ "match": { "pattern": "database.*production" } }
```

### Actions

- `allow` — Explicitly allow the action (overrides blocks)
- `block` — Prevent the action and log violation
- `warn` — Allow but log a warning

### Example Policy

```json
{
  "name": "data-protection",
  "description": "Prevent access to sensitive data",
  "version": "1.0.0",
  "rules": [
    {
      "id": "block-secrets",
      "description": "Block access to secrets directory",
      "match": { "path": "/secrets/**" },
      "action": "block",
      "message": "Access to secrets directory prohibited"
    },
    {
      "id": "warn-force-push",
      "description": "Warn on force pushes",
      "match": {
        "tool": "Bash",
        "command": "git push.*--force"
      },
      "action": "warn",
      "message": "Force push detected — ensure this is intentional"
    },
    {
      "id": "block-rm-rf",
      "description": "Block dangerous recursive deletes",
      "match": {
        "tool": "Bash",
        "command": "rm\\s+-rf\\s+/"
      },
      "action": "block",
      "message": "Recursive delete from root not allowed"
    }
  ]
}
```

### Multiple Match Conditions

All specified conditions must match (AND logic):

```json
{
  "match": {
    "tool": "Write",
    "path": "**/.env*"
  },
  "action": "block",
  "message": "Cannot write to environment files"
}
```

This blocks only Write operations to .env files, but allows Read operations.

## License

MIT
