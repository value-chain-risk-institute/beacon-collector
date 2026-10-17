"""
spool.py: read the hook spool for sealing (element H18, source claude-code-hook).

Every tick re-walks each day's spool from the first line and recomputes the hash
chain, then compares it against the cursor sealed last time (line count + head
hash). Findings are facts with a location, never verdicts:
  chain_break           a line's prev does not match the line before it
  sealed_prefix_changed a line we already sealed is no longer the line we sealed
  spool_file_missing    a day we sealed lines from is gone
  unparseable_line      a line that is not JSON
New lines past the cursor are returned for this tick's segment.
"""
import glob
import json
import os

import actionlib as al


def read(state_dir, cursors):
    """Returns (new_records, new_cursors, findings, stats)."""
    spool = os.path.join(os.path.expanduser(state_dir), "actions", "spool")
    files = sorted(glob.glob(os.path.join(spool, "*.jsonl")))
    new_records, findings = [], []
    new_cursors = {}
    stats = {"files": len(files), "lines_total": 0, "lines_new": 0}
    seen = set()
    for path in files:
        name = os.path.basename(path)
        seen.add(name)
        cur = cursors.get(name, {"lines": 0, "head": None})
        # Two hashes per line. `local` is what the writer chained on (each line's own
        # prev + its bytes), so a break is reported once, where it happens.
        # `running` folds every line from the top, so ANY change to a sealed line
        # moves the head the cursor recorded, even when the edit kept its local link.
        prev_hash, running, n = None, None, 0
        head_at_cursor = None
        with open(path, "rb") as f:
            for raw in f:
                line = raw.rstrip(b"\n")
                if not line:
                    continue
                n += 1
                running = al.line_hash(running, line)
                try:
                    obj = json.loads(line)
                except ValueError:
                    findings.append({"finding": "unparseable_line", "file": name, "line": n})
                    prev_hash = al.line_hash(prev_hash, line)
                else:
                    if obj.get("prev") != prev_hash:
                        findings.append({"finding": "chain_break", "file": name, "line": n})
                    prev_hash = al.line_hash(obj.get("prev"), line)
                    if n > cur["lines"]:
                        rec = obj.get("rec", {})
                        rec["spool"] = {"file": name, "line": n, "line_hash": prev_hash}
                        new_records.append(rec)
                if n == cur["lines"]:
                    head_at_cursor = running
        if cur["lines"] and (n < cur["lines"] or head_at_cursor != cur["head"]):
            findings.append({"finding": "sealed_prefix_changed", "file": name,
                             "sealed_lines": cur["lines"], "lines_now": n})
        stats["lines_total"] += n
        stats["lines_new"] += max(0, n - cur["lines"])
        new_cursors[name] = {"lines": n, "head": running}
    for name, cur in cursors.items():
        if name not in seen:
            findings.append({"finding": "spool_file_missing", "file": name,
                             "sealed_lines": cur.get("lines")})
            new_cursors[name] = cur  # keep the claim alive so the absence stays visible
    return new_records, new_cursors, findings, stats


def failures(state_dir):
    p = os.path.join(os.path.expanduser(state_dir), "actions", "hook-failures.json")
    try:
        with open(p) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"count": 0, "by_type": {}}
