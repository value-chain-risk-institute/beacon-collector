#!/usr/bin/env python3
"""
beacon_action_hook.py: Claude Code hook that writes one metadata-only line per
agent event into a hash-chained daily spool the collector seals (element H18).

Register it for any of: SessionStart, UserPromptSubmit, PreToolUse, PostToolUse,
PostToolUseFailure, PermissionRequest, SubagentStart, SubagentStop, PreCompact,
Stop, ConfigChange. Same command for all; it reads hook_event_name from stdin.

Rules (spec v0.3, plan section 3.3):
  - Never blocks, never decides, never prints: exit 0 always, so a broken collector
    can never change what the agent does. Failures go to a counter the collector
    seals, so a quietly failing hook is visible rather than silent.
  - No network. Standard library only. Deterministic (no generative component).
  - Content is committed per item (see actionlib), never stored. Session ids become keyed pseudonyms.
  - Each line carries the hash of the line before it; editing, deleting or
    reordering a line breaks the day's chain, and the collector says where.

State dir: $BEACON_STATE or ~/.beacon/agent. Spool: <state>/actions/spool/YYYY-MM-DD.jsonl
"""
import fcntl
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sources"))
import actionlib as al  # noqa: E402

EVENT_MAP = {
    "SessionStart": "session_start", "SessionEnd": "session_end",
    "UserPromptSubmit": "prompt",
    "PreToolUse": "tool_call", "PostToolUse": "tool_result",
    "PostToolUseFailure": "tool_result", "PermissionRequest": "permission_request",
    "SubagentStart": "subagent_start", "SubagentStop": "subagent_stop",
    "PreCompact": "compaction", "Stop": "turn_end", "ConfigChange": "config_change",
    "Notification": "notification",
}


def build(payload, key, now):
    ev_name = str(payload.get("hook_event_name") or "unknown")
    clear = {k: payload[k] for k in al.CLEAR_FIELDS if k in payload and k != "model"}
    commits, sizes = {}, {}
    item = payload.get("tool_use_id") or payload.get("prompt_id") or \
        al.ref(key, payload.get("session_id")) or "unscoped"
    for k in al.COMMIT_FIELDS:
        if k in payload and payload[k] is not None:
            commits[k] = al.commit(key, payload[k], "%s:%s" % (k, item))
            sizes[k + "_bytes"] = al.size(payload[k])
    # Unknown fields are counted by name, never stored: a harness adding a content
    # field in a minor release must not leak it into evidence.
    known = set(al.CLEAR_FIELDS) | set(al.COMMIT_FIELDS) | {"session_id", "hook_event_name"}
    unknown = sorted(k for k in payload if k not in known)
    rec = al.record(
        "claim", "claude-code-hook", EVENT_MAP.get(ev_name, ev_name.lower()),
        now, "hook-clock",
        agent={"harness": "claude-code",
               "session_ref": al.ref(key, payload.get("session_id")),
               "agent_id": payload.get("agent_id"), "agent_type": payload.get("agent_type")},
        correlation={"tool_use_id": payload.get("tool_use_id"),
                     "prompt_id": payload.get("prompt_id")},
        model={"requested": payload.get("model")} if payload.get("model") else {},
        tool={"name": payload.get("tool_name"),
              "failed": ev_name == "PostToolUseFailure"} if payload.get("tool_name") else {},
        content_commitments=commits, sizes=sizes)
    rec["hook"] = {"event": ev_name, "clear": clear, "unknown_fields": unknown,
                   "key_id": al.key_id(key)}
    return rec


def last_hash(f):
    """Hash of the final line in an open spool, recomputed from its own prev field."""
    f.seek(0, os.SEEK_END)
    end = f.tell()
    if end == 0:
        return None
    pos = max(0, end - 65536)
    f.seek(pos)
    tail = f.read().rstrip(b"\n").rsplit(b"\n", 1)[-1]
    try:
        prev = json.loads(tail).get("prev")
    except ValueError:
        return "unparseable-tail"
    return al.line_hash(prev, tail)


def append(state_dir, rec, now_dt):
    spool = os.path.join(al.actions_dir(state_dir), "spool")
    os.makedirs(spool, mode=0o700, exist_ok=True)
    path = os.path.join(spool, now_dt.strftime("%Y-%m-%d") + ".jsonl")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "r+b") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            prev = last_hash(f)
            line = json.dumps({"prev": prev, "rec": rec}, sort_keys=True,
                              separators=(",", ":")).encode()
            f.seek(0, os.SEEK_END)
            f.write(line + b"\n")
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    return path


def note_failure(state_dir, err):
    try:
        p = os.path.join(al.actions_dir(state_dir), "hook-failures.json")
        try:
            with open(p) as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = {"count": 0, "by_type": {}}
        d["count"] += 1
        d["by_type"][err] = d["by_type"].get(err, 0) + 1
        d["last_utc"] = datetime.now(timezone.utc).isoformat()
        with open(p, "w") as f:
            json.dump(d, f)
    except Exception:
        pass


def main():
    state_dir = os.environ.get("BEACON_STATE", "~/.beacon/agent")
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        if not isinstance(payload, dict):
            raise ValueError("payload not an object")
        now_dt = datetime.now(timezone.utc)
        key = al.load_key(state_dir)
        append(state_dir, build(payload, key, now_dt.isoformat()), now_dt)
    except Exception as e:
        note_failure(state_dir, type(e).__name__)
    sys.exit(0)


if __name__ == "__main__":
    main()
