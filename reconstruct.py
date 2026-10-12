#!/usr/bin/env python3
"""
reconstruct.py: turn sealed agent-action packages into an incident timeline.

Two roles, kept apart on purpose:

  open      ORG side. Holds the deployment key and the raw local transcripts. For
            the items it chooses (by tool_use_id), it emits OPENINGS: the exact
            bytes plus that item's nonce. Nothing else is revealed: no key, no
            other item.

  timeline  EXAMINER side. Needs no key and trusts no one. Verifies each package
            and its blobs, rebuilds the per-session sequence of prompts, model
            turns, tool calls and results from the sealed H18 segment, shows
            which claim sources saw each call (H22), and, for any opening it is
            given, checks the bytes against the sealed commitment before showing
            them. An opening that does not match is reported as NOT MATCHING and
            its content is not shown.

Usage:
  reconstruct.py open --state DIR --transcript-root DIR --tool-use-id ID [...] > openings.json
  reconstruct.py timeline PKG_DIR [PKG_DIR ...] [--openings openings.json] [--html out.html]

What it does not do: decide what happened. It lays out sealed facts in time order
with their grade; the reading belongs to the examiner.
"""
import argparse
import glob
import html
import io
import json
import os
import sys
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "sources"))
import actionlib as al  # noqa: E402
import beaconlib as bl  # noqa: E402


# ---------------- org side ----------------

def cmd_open(args):
    key = al.load_key(args.state, create=False)
    if key is None:
        sys.exit("no deployment key under %s/actions; only the org that sealed can open" % args.state)
    want = set(args.tool_use_id)
    fields = set(args.field)
    openings = []
    for path in glob.glob(os.path.join(os.path.expanduser(args.transcript_root), "**", "*.jsonl"),
                          recursive=True):
        with open(path, "rb") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                msg = obj.get("message") if isinstance(obj, dict) else None
                content = msg.get("content") if isinstance(msg, dict) else None
                for b in content if isinstance(content, list) else []:
                    if not isinstance(b, dict):
                        continue
                    if b.get("type") == "tool_use" and b.get("id") in want and "tool_input" in fields:
                        openings.append(al.opening(key, b.get("input"), "tool_input:" + b["id"]))
                    if b.get("type") == "tool_result" and b.get("tool_use_id") in want \
                            and "tool_response" in fields:
                        openings.append(al.opening(key, b.get("content"),
                                                   "tool_response:" + b["tool_use_id"]))
    found = {o["scope"].split(":", 1)[1] for o in openings}
    for t in sorted(want - found):
        print("not found in local transcripts: %s" % t, file=sys.stderr)
    json.dump({"openings": openings,
               "note": "each opening reveals one item: its bytes and its nonce, never the key"},
              sys.stdout, indent=2)
    print()


# ---------------- examiner side ----------------

def verify_state(pkg, blob_dir):
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            ok = bl.verify_package(pkg, blob_dir=blob_dir)
        except Exception as e:
            return "unproven", "verifier error: %s" % type(e).__name__
    out = buf.getvalue()
    if "REJECT" in out or "TAMPERED" in out or "MISSING blob" in out:
        return "tampered", out.strip().splitlines()[0]
    if ok and "VALID" in out:
        return "verified", ""
    return "unproven", out.strip().splitlines()[-1] if out.strip() else ""


def load_segment(pkg_dir, pkg):
    for it in pkg.get("items", []):
        if it.get("subcriterion") == "agent-v0:H18":
            rh = it.get("source", {}).get("raw_sha256")
            p = os.path.join(pkg_dir, "blobs", "sha256-%s.json" % rh)
            if os.path.isfile(p):
                with open(p) as f:
                    return json.load(f).get("records", []), it
            return [], it
    return [], None


def build(pkg_dirs, openings):
    by_commit = {}
    for o in openings:
        by_commit.setdefault(o["scope"], []).append(o)
    packages, calls, sessions = [], {}, {}
    for d in pkg_dirs:
        with open(os.path.join(d, "package.json")) as f:
            pkg = json.load(f)
        state, why = verify_state(pkg, os.path.join(d, "blobs"))
        recs, h18 = load_segment(d, pkg)
        h22 = next((it["observation"] for it in pkg["items"]
                    if it.get("subcriterion") == "agent-v0:H22"), None)
        packages.append({"dir": d, "sequence": pkg.get("chain", {}).get("sequence"),
                         "package_hash": pkg["seal"]["package_hash"], "verify": state,
                         "why": why, "records": len(recs),
                         "signed": pkg["seal"].get("signature", {}).get("alg") == "ed25519",
                         "pairing": (h22 or {}).get("pairing")})
        if state == "tampered":
            continue  # a tampered package contributes nothing to the timeline
        for r in recs:
            sess = r.get("agent", {}).get("session_ref") or "unknown-session"
            sessions.setdefault(sess, []).append(r)
            tid = r.get("correlation", {}).get("tool_use_id")
            if tid and r.get("event") in ("tool_call", "tool_result"):
                c = calls.setdefault(tid, {"sources": set(), "tool": None, "is_error": None,
                                           "commitments": {}, "opened": {}})
                c["sources"].add(r["source"])
                c["tool"] = c["tool"] or r.get("tool", {}).get("name")
                if r.get("tool", {}).get("is_error") is not None:
                    c["is_error"] = r["tool"]["is_error"]
                for field, cm in (r.get("content_commitments") or {}).items():
                    if field in ("tool_input", "tool_response") and cm:
                        c["commitments"].setdefault(field, set()).add(cm)
    for tid, c in calls.items():
        for field, cms in c["commitments"].items():
            for o in by_commit.get("%s:%s" % (field, tid), []):
                match = any(al.check_opening(cm, o) for cm in cms)
                c["opened"][field] = {"matches_sealed_commitment": match,
                                      "value": (json.loads(_b64(o)) if match and _is_json(o)
                                                else (_b64(o) if match else None))}
    for sess in sessions.values():
        sess.sort(key=lambda r: (r.get("ts_utc") or "", r.get("source") != "claude-code-hook"))
    return packages, sessions, calls


def _b64(o):
    import base64
    return base64.b64decode(o["value_b64"]).decode("utf-8", "replace")


def _is_json(o):
    try:
        json.loads(_b64(o))
        return True
    except ValueError:
        return False


def render_text(packages, sessions, calls):
    out = ["# Agent incident reconstruction", ""]
    out.append("## Packages")
    for p in packages:
        out.append("- seq %s %s (%s, %s, %d action records)%s" % (
            p["sequence"], p["package_hash"][:16], p["verify"].upper(),
            "signed" if p["signed"] else "unsigned", p["records"],
            (": " + p["why"]) if p["why"] else ""))
    out.append("")
    for sess, recs in sessions.items():
        out.append("## Session %s" % sess[:22])
        seen_calls = set()
        for r in recs:
            ev, src = r.get("event"), r.get("source", "").replace("claude-code-", "")
            ts = (r.get("ts_utc") or "")[:23]
            tid = r.get("correlation", {}).get("tool_use_id")
            if ev == "model_turn":
                m = r.get("model", {})
                out.append("%s  model turn     served=%s requested=%s  [%s]" % (
                    ts, m.get("served"), m.get("requested") or "unrecorded", src))
            elif ev == "tool_call" and tid not in seen_calls:
                seen_calls.add(tid)
                c = calls.get(tid, {})
                srcs = ",".join(sorted(s.replace("claude-code-", "") for s in c.get("sources", [])))
                out.append("%s  TOOL CALL      %s %s  seen by: %s" % (ts, c.get("tool"), tid, srcs))
                for field, o in c.get("opened", {}).items():
                    if o["matches_sealed_commitment"]:
                        out.append("                 opened %s (matches sealed commitment): %s"
                                   % (field, json.dumps(o["value"])[:300]))
                    else:
                        out.append("                 opening for %s DOES NOT MATCH the sealed "
                                   "commitment; content withheld" % field)
            elif ev == "tool_result" and r.get("source") == "claude-code-transcript":
                c = calls.get(tid, {})
                out.append("%s  tool result    %s error=%s" % (ts, tid, c.get("is_error")))
            elif ev in ("prompt", "session_start", "turn_end") and r.get("source") == "claude-code-hook":
                out.append("%s  %-14s [%s]" % (ts, ev.replace("_", " "), src))
        out.append("")
    out.append("## Pairing (H22, derived)")
    for p in packages:
        pr = p.get("pairing") or {}
        if pr.get("present"):
            out.append("- seq %s: %d calls in both sources, hook only %s, transcript only %s, "
                       "input differs %s" % (p["sequence"], pr["in_both"], pr["hook_not_transcript"],
                                             pr["transcript_not_hook"], pr["input_commitment_differs"]))
        else:
            out.append("- seq %s: not paired (%s)" % (p["sequence"], pr.get("note", "no H22")))
    out.append("")
    out.append("Grade: every record above is the agent's or harness's own account (claim side). "
               "Agreement between hook and transcript is consistency, not observation. No OS "
               "observer or vendor record was configured for this window, so an effect absent "
               "here is not observed, not shown not to have happened.")
    return "\n".join(out)


def cmd_timeline(args):
    openings = []
    if args.openings:
        with open(args.openings) as f:
            openings = json.load(f).get("openings", [])
    packages, sessions, calls = build(args.pkg_dirs, openings)
    text = render_text(packages, sessions, calls)
    print(text)
    if args.html:
        page = ("<!doctype html><meta charset=utf-8><title>Agent incident reconstruction</title>"
                "<style>body{font:14px/1.5 ui-monospace,Menlo,monospace;margin:24px;"
                "background:#fff;color:#111}@media (prefers-color-scheme:dark){body{"
                "background:#111;color:#e6e6e6}}pre{white-space:pre-wrap}</style>"
                "<pre>%s</pre>" % html.escape(text))
        with open(args.html, "w") as f:
            f.write(page)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("open", help="ORG side: emit openings for chosen tool calls")
    o.add_argument("--state", default="~/.beacon/agent")
    o.add_argument("--transcript-root", default="~/.claude/projects")
    o.add_argument("--tool-use-id", action="append", required=True)
    o.add_argument("--field", action="append", default=None,
                   choices=["tool_input", "tool_response"])
    t = sub.add_parser("timeline", help="EXAMINER side: verify and lay out sealed actions")
    t.add_argument("pkg_dirs", nargs="+")
    t.add_argument("--openings")
    t.add_argument("--html")
    args = ap.parse_args()
    if args.cmd == "open":
        args.field = args.field or ["tool_input"]
        cmd_open(args)
    else:
        cmd_timeline(args)


if __name__ == "__main__":
    main()
