"""
claude_transcripts.py: Claude Code session transcripts as an action source (H18)
and as the first real source for A2 (the model that actually served each turn).

The transcript is the harness's own record, so it is CLAIM side (testimony), not
observation. What makes it useful anyway:
  - every assistant record carries the API response's `model` field, which the
    provider sets to the model that produced the message (including after a
    fallback), next to the harness's `requestedModel`;
  - every record carries vendor correlation ids (requestId, message id,
    tool_use id) that line up with Anthropic's own server-side record;
  - we seal a prefix (length + SHA-256) of every transcript each tick, so a later
    edit to an already-sealed portion is a located finding. No current tool can
    say that a transcript was rewritten after the fact; this can.

Cost control: a file whose size and mtime match its cursor is not re-hashed
(mtime can be forged, so that shortcut is stated in the coverage note). On the
first run, files older than the lookback are baselined at their current length
and NOT ingested; the count is reported, so history before enrollment is a
declared gap, never a silent one.
"""
import glob
import hashlib
import json
import os
import time

import actionlib as al

DEFAULT_ROOT = "~/.claude/projects"
LOOKBACK_SECONDS = 24 * 3600
MAX_NEW_BYTES_PER_TICK = 256 * 1024 * 1024


def _prefix_sha(path, length):
    h = hashlib.sha256()
    remaining = length
    with open(path, "rb") as f:
        while remaining > 0:
            chunk = f.read(min(1 << 20, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)
    return h.hexdigest(), length - remaining


def _complete_suffix(path, start):
    """Bytes from start up to the last newline (a half-written last line waits)."""
    with open(path, "rb") as f:
        f.seek(start)
        data = f.read(MAX_NEW_BYTES_PER_TICK)
    cut = data.rfind(b"\n")
    return data[:cut + 1] if cut >= 0 else b""


def _perm(value, key, scope):
    if isinstance(value, str) and len(value) <= 40:
        return {"decision": value}
    if isinstance(value, dict):
        d = value.get("decision") or value.get("behavior")
        if isinstance(d, str) and len(d) <= 40:
            return {"decision": d}
    return {"decision_commitment": al.commit(key, value, "permission:" + str(scope))} if value is not None else {}


def extract(line_obj, key, rel):
    """One transcript record -> zero or more action records."""
    out = []
    t = line_obj.get("type")
    ts = line_obj.get("timestamp")
    session_ref = al.ref(key, line_obj.get("sessionId"))
    agent = {"harness": "claude-code", "version": line_obj.get("version"),
             "session_ref": session_ref, "sidechain": line_obj.get("isSidechain"),
             "entrypoint": line_obj.get("entrypoint")}
    msg = line_obj.get("message") if isinstance(line_obj.get("message"), dict) else {}
    content = msg.get("content")
    if t == "assistant":
        usage = msg.get("usage") or {}
        model = {"requested": line_obj.get("requestedModel"), "served": msg.get("model"),
                 "served_source": "api-response-field"}
        corr = {"request_id": line_obj.get("requestId"), "message_id": msg.get("id"),
                "uuid": line_obj.get("uuid")}
        out.append(al.record(
            "claim", "claude-code-transcript", "model_turn", ts, "agent-clock",
            agent=agent, correlation=corr, model=model,
            sizes={"input_tokens": usage.get("input_tokens"),
                   "output_tokens": usage.get("output_tokens"),
                   "cache_read_input_tokens": usage.get("cache_read_input_tokens"),
                   "service_tier": usage.get("service_tier"),
                   "inference_geo": usage.get("inference_geo")}))
        for b in content if isinstance(content, list) else []:
            if isinstance(b, dict) and b.get("type") in ("tool_use", "server_tool_use"):
                out.append(al.record(
                    "claim", "claude-code-transcript", "tool_call", ts, "agent-clock",
                    agent=agent, model=model,
                    correlation={"request_id": line_obj.get("requestId"),
                                 "message_id": msg.get("id"), "tool_use_id": b.get("id")},
                    tool={"name": b.get("name")},
                    content_commitments={"tool_input": al.commit(key, b.get("input"), "tool_input:" + str(b.get("id")))},
                    sizes={"tool_input_bytes": al.size(b.get("input"))}))
    elif t == "user":
        corr = {"prompt_id": line_obj.get("promptId"), "uuid": line_obj.get("uuid")}
        blocks = content if isinstance(content, list) else []
        results = [b for b in blocks if isinstance(b, dict) and b.get("type") == "tool_result"]
        for b in results:
            tool = {"is_error": bool(b.get("is_error"))}
            if "permissionDecision" in line_obj:
                tool.update(_perm(line_obj.get("permissionDecision"), key, b.get("tool_use_id")))
            out.append(al.record(
                "claim", "claude-code-transcript", "tool_result", ts, "agent-clock",
                agent=agent, correlation={**corr, "tool_use_id": b.get("tool_use_id")},
                tool=tool,
                content_commitments={"tool_response": al.commit(key, b.get("content"), "tool_response:" + str(b.get("tool_use_id")))},
                sizes={"tool_response_bytes": al.size(b.get("content"))}))
        if not results and content is not None:
            out.append(al.record(
                "claim", "claude-code-transcript", "prompt", ts, "agent-clock",
                agent=agent, correlation=corr,
                content_commitments={"prompt": al.commit(key, content, "prompt:" + str(line_obj.get("promptId") or line_obj.get("uuid")))},
                sizes={"prompt_bytes": al.size(content)}))
    for r in out:
        r["transcript"] = {"file_ref": al.ref(key, rel)}
    return out


def read(cursors, key, root=DEFAULT_ROOT, now=None, lookback=LOOKBACK_SECONDS):
    """Returns (records, new_cursors, findings, stats). cursors maps rel path ->
    {"bytes", "sha256", "size", "mtime"}; None means first run (baseline)."""
    root = os.path.expanduser(root)
    now = now or time.time()
    first_run = cursors is None
    cursors = cursors or {}
    files = sorted(glob.glob(os.path.join(root, "**", "*.jsonl"), recursive=True))
    records, findings, new_cursors = [], [], {}
    stats = {"files": len(files), "files_changed": 0, "bytes_new": 0,
             "baselined_not_ingested": 0, "lines_unparseable": 0, "truncated_reads": 0}
    seen, seen_turns = set(), set()
    for path in files:
        rel = os.path.relpath(path, root)
        seen.add(rel)
        try:
            st = os.stat(path)
        except OSError:
            continue
        cur = cursors.get(rel)
        if cur and cur.get("size") == st.st_size and cur.get("mtime") == st.st_mtime:
            new_cursors[rel] = cur
            continue
        start = 0
        if cur:
            sha, got = _prefix_sha(path, cur["bytes"])
            if got < cur["bytes"] or sha != cur["sha256"]:
                findings.append({"finding": "sealed_prefix_changed",
                                 "file_ref": al.ref(key, rel),
                                 "sealed_bytes": cur["bytes"], "bytes_now": st.st_size})
                start = 0 if got < cur["bytes"] else cur["bytes"]
            else:
                start = cur["bytes"]
        elif first_run and now - st.st_mtime > lookback:
            sha, got = _prefix_sha(path, st.st_size)
            new_cursors[rel] = {"bytes": got, "sha256": sha, "size": st.st_size,
                                "mtime": st.st_mtime}
            stats["baselined_not_ingested"] += 1
            continue
        data = _complete_suffix(path, start)
        if len(data) >= MAX_NEW_BYTES_PER_TICK:
            stats["truncated_reads"] += 1
        stats["files_changed"] += 1
        stats["bytes_new"] += len(data)
        for line in data.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                stats["lines_unparseable"] += 1
                continue
            if isinstance(obj, dict):
                for r in extract(obj, key, rel):
                    # The harness writes one record per content block, each repeating
                    # the message id; count a model turn once per message.
                    mid = r["correlation"].get("message_id") if r["event"] == "model_turn" else None
                    if mid:
                        if mid in seen_turns:
                            continue
                        seen_turns.add(mid)
                    records.append(r)
        end = start + len(data)
        sha, _ = _prefix_sha(path, end)
        new_cursors[rel] = {"bytes": end, "sha256": sha, "size": st.st_size,
                            "mtime": st.st_mtime}
    gone = sorted(set(cursors) - seen)
    if gone:
        # Claude Code deletes old transcripts on its own schedule (cleanupPeriodDays).
        # Recorded once, as a retention event; the sealed cursors are the proof of
        # what existed.
        findings.append({"finding": "transcripts_removed", "count": len(gone),
                         "file_refs": [al.ref(key, g) for g in gone[:200]]})
    return records, new_cursors, findings, stats


def served_models(records):
    """A2 summary: per (requested, served) pair, turn counts. Facts, no verdict."""
    pairs = {}
    for r in records:
        if r.get("event") != "model_turn":
            continue
        m = r.get("model", {})
        k = (m.get("requested") or "unrecorded", m.get("served") or "unrecorded")
        pairs[k] = pairs.get(k, 0) + 1
    return [{"requested": k[0], "served": k[1], "turns": v,
             "strings_differ": k[0] != "unrecorded" and k[0] != k[1]}
            for k, v in sorted(pairs.items())]
