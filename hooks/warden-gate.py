#!/usr/bin/env python3
"""
Warden Gate — PreToolUse Hook
Enforces policies on every tool action before execution.

Install in .claude/settings.json:
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "",
      "hooks": [{ "type": "command", "command": "python3 ~/warden/hooks/warden-gate.py" }]
    }]
  }
}
"""

import json
import sys
import os
import re
from pathlib import Path
from datetime import datetime

POLICIES_DIR = Path(__file__).parent.parent / "policies"
WARDEN_DIR = Path.home() / ".warden"
GATE_LOG = WARDEN_DIR / "gate.jsonl"


def load_policies():
    """Load all JSON policy files from the policies directory."""
    policies = []
    if not POLICIES_DIR.exists():
        return policies
    for f in POLICIES_DIR.glob("*.json"):
        try:
            with open(f) as fh:
                policy = json.load(fh)
                if "name" in policy and "rules" in policy:
                    policies.append(policy)
        except (json.JSONDecodeError, IOError):
            continue
    return policies


def match_rule(rule, action):
    """Check if a rule matches the given action."""
    match = rule.get("match", {})
    if not match:
        return False

    # Tool match
    if "tool" in match:
        if action.get("tool", "").lower() != match["tool"].lower():
            return False

    # Command match (regex)
    if "command" in match:
        cmd = action.get("command", "")
        if not cmd:
            return False
        try:
            if not re.search(match["command"], cmd, re.IGNORECASE):
                return False
        except re.error:
            if match["command"].lower() not in cmd.lower():
                return False

    # Path match (prefix/glob)
    if "path" in match:
        path = action.get("path", "")
        if not path:
            return False
        normalized = match["path"].replace("*", "")
        if not path.startswith(normalized) and normalized not in path:
            return False

    # Pattern match (regex against full action JSON)
    if "pattern" in match:
        serialized = json.dumps(action)
        try:
            if not re.search(match["pattern"], serialized, re.IGNORECASE):
                return False
        except re.error:
            if match["pattern"].lower() not in serialized.lower():
                return False

    return True


def evaluate_action(action, policies):
    """Evaluate an action against all policies. Return violations."""
    violations = []
    for policy in policies:
        for rule in policy.get("rules", []):
            if match_rule(rule, action) and rule.get("action") in ("block", "warn"):
                violations.append({
                    "policy": policy["name"],
                    "rule_description": rule.get("description", ""),
                    "severity": "critical" if rule["action"] == "block" else "warning",
                    "action": rule["action"],
                })
    return violations


def log_gate_decision(action, violations, decision):
    """Log the gate decision to gate.jsonl."""
    WARDEN_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
        "tool": action.get("tool", "unknown"),
        "command": action.get("command"),
        "path": action.get("path"),
        "violations": violations,
        "decision": decision,
    }
    with open(GATE_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def extract_action_from_input(hook_input):
    """Extract action details from Claude Code hook input."""
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    action = {"tool": tool_name}

    if tool_name == "Bash":
        action["command"] = tool_input.get("command", "")
    elif tool_name in ("Read", "Write", "Edit", "Glob"):
        action["path"] = (
            tool_input.get("file_path")
            or tool_input.get("path")
            or tool_input.get("pattern", "")
        )
    elif tool_name == "Grep":
        action["command"] = tool_input.get("pattern", "")
        action["path"] = tool_input.get("path", "")

    action["params"] = tool_input
    return action


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        sys.exit(0)

    try:
        hook_input = json.loads(raw)
    except json.JSONDecodeError:
        sys.exit(0)

    action = extract_action_from_input(hook_input)
    policies = load_policies()
    violations = evaluate_action(action, policies)

    blocks = [v for v in violations if v["severity"] == "critical"]
    warnings = [v for v in violations if v["severity"] == "warning"]

    if blocks:
        decision = "blocked"
        log_gate_decision(action, violations, decision)
        reason = blocks[0]["rule_description"] or blocks[0]["policy"]
        result = {
            "decision": "block",
            "reason": f"WARDEN POLICY VIOLATION [{blocks[0]['policy']}]: {reason}",
        }
        print(json.dumps(result))
        sys.exit(2)
    elif warnings:
        decision = "warned"
        log_gate_decision(action, violations, decision)
        # Warnings don't block — just log
        sys.exit(0)
    else:
        log_gate_decision(action, [], "allowed")
        sys.exit(0)


if __name__ == "__main__":
    main()
