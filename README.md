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

## Policy Format

Policies are defined as JSON files in the `policies/` directory:

```json
{
  "name": "data-protection",
  "description": "Prevent access to sensitive data",
  "rules": [
    {
      "match": { "path": "/secrets/*" },
      "action": "block",
      "description": "Block access to secrets directory"
    },
    {
      "match": { "tool": "Bash", "command": "rm -rf" },
      "action": "warn",
      "description": "Warn on dangerous commands"
    }
  ]
}
```

## License

MIT
