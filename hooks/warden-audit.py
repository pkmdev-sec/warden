#!/usr/bin/env python3
"""
Warden Audit — PostToolUse Hook
Logs every tool action to the audit trail for compliance tracking.

Install in .claude/settings.json:
{
  "hooks": {
    "PostToolUse": [{
      "matcher": "",
      "hooks": [{ "type": "command", "command": "python3 ~/warden/hooks/warden-audit.py" }]
    }]
  }
}
"""

import json
import sys
import os
import uuid
from pathlib import Path
from datetime import datetime

WARDEN_DIR = Path.home() / ".warden"
AUDIT_LOG = WARDEN_DIR / "audit.jsonl"


def ensure_audit_dir():
    """Ensure the ~/.warden directory and audit.jsonl exist."""
    WARDEN_DIR.mkdir(parents=True, exist_ok=True)
    if not AUDIT_LOG.exists():
        AUDIT_LOG.touch()


def extract_audit_entry(hook_input):
    """Build an audit log entry from the PostToolUse hook input."""
    tool_name = hook_input.get("tool_name", "unknown")
    tool_input = hook_input.get("tool_input", {})
    tool_output = hook_input.get("tool_output", {})

    # Determine result status
    output_str = str(tool_output)
    if "error" in output_str.lower() or "failed" in output_str.lower():
        result = "error"
    elif "blocked" in output_str.lower() or "denied" in output_str.lower():
        result = "blocked"
    else:
        result = "success"

    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
        "user": os.environ.get("USER", "unknown"),
        "tool": tool_name,
        "command": None,
        "path": None,
        "params": {},
        "result": result,
        "violations": [],
        "metadata": {
            "hook": "PostToolUse",
            "session": os.environ.get("CLAUDE_SESSION_ID", "unknown"),
        },
    }

    # Extract tool-specific details
    if tool_name == "Bash":
        entry["command"] = tool_input.get("command", "")
    elif tool_name in ("Read", "Write", "Edit"):
        entry["path"] = tool_input.get("file_path", "")
    elif tool_name == "Glob":
        entry["path"] = tool_input.get("pattern", "")
    elif tool_name == "Grep":
        entry["command"] = tool_input.get("pattern", "")
        entry["path"] = tool_input.get("path", "")
    elif tool_name == "NotebookEdit":
        entry["path"] = tool_input.get("notebook_path", "")
    elif tool_name == "WebFetch":
        entry["path"] = tool_input.get("url", "")

    # Truncate large params for storage efficiency
    params = dict(tool_input)
    for key in params:
        if isinstance(params[key], str) and len(params[key]) > 500:
            params[key] = params[key][:500] + "...[truncated]"
    entry["params"] = params

    return entry


def log_entry(entry):
    """Append an audit entry to the JSONL log."""
    ensure_audit_dir()
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        sys.exit(0)

    try:
        hook_input = json.loads(raw)
    except json.JSONDecodeError:
        sys.exit(0)

    entry = extract_audit_entry(hook_input)
    log_entry(entry)

    # PostToolUse hooks should exit cleanly
    sys.exit(0)


if __name__ == "__main__":
    main()
