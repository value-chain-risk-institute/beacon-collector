#!/usr/bin/env python3
"""
test_agentmode.py: agent mode had no tests of its own until v0.3. These cover the
release gates in the build plan that can run on one machine:

  - canonicalization stability over every package already sealed (exactly zero
    mismatches; nonzero is a defect, not a rate)
  - the hook spool: chain, tamper, deletion, failure counter, no content in clear
  - the transcript reader: baseline, increments, rewritten prefix, removal, A2
  - pairing (H22) arithmetic
  - MCP client inventory never records env values or URL paths
  - a full collect into a scratch state, verify-chain, and a tampered segment

Run: ~/.beacon/venv/bin/python test_agentmode.py
Reads ~/.beacon/agent/packages read-only for the stability gate; writes only to
temporary directories.
"""
import glob
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "sources"))
import actionlib as al  # noqa: E402
import beaconlib as bl  # noqa: E402
import claude_transcripts as ct  # noqa: E402
import clients  # noqa: E402
import pairing  # noqa: E402
import spool  # noqa: E402

HOOK = os.path.join(HERE, "hooks", "beacon_action_hook.py")
SECRET = "CANARY-do-not-store-7f3a"
LIVE_PACKAGES = os.path.expanduser("~/.beacon/agent/packages")


def run_hook(state, payload, raw=None):
    env = {**os.environ, "BEACON_STATE": state}
    data = raw if raw is not None else json.dumps(payload)
    return subprocess.run([sys.executable, HOOK], input=data.encode(), env=env,
                          capture_output=True, timeout=20)


def tx_line(kind, **kw):
    base = {"type": kind, "sessionId": "sess-1", "timestamp": "2026-10-12T00:00:00Z",
            "uuid": kw.pop("uuid", "u"), "version": "2.1.296", "isSidechain": False}
    base.update(kw)
    return json.dumps(base) + "\n"


def assistant(msg_id, tool_id=None, tool_input=None, requested="claude-opus-5-5",
              served="claude-opus-5-5"):
    content = [{"type": "text", "text": SECRET}]
    if tool_id:
        content.append({"type": "tool_use", "id": tool_id, "name": "Bash",
                        "input": tool_input or {"command": "echo " + SECRET}})
    return tx_line("assistant", requestId="req_" + msg_id, requestedModel=requested,
                   message={"id": msg_id, "model": served, "role": "assistant",
                            "content": content, "usage": {"input_tokens": 3, "output_tokens": 5}})


def tool_result(tool_id):
    return tx_line("user", message={"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": tool_id, "content": SECRET, "is_error": False}]})


class StabilityGate(unittest.TestCase):
    def test_every_sealed_package_rehashes_identically(self):
        paths = sorted(glob.glob(os.path.join(LIVE_PACKAGES, "*", "package.json")))
        if not paths:
            self.skipTest("no live packages on this machine")
        mismatches = []
        for p in paths:
            with open(p) as f:
                pkg = json.load(f)
            for it in pkg.get("items", []):
                if bl.hash_item(it) != it.get("item_sha256"):
                    mismatches.append((p, it.get("subcriterion")))
            core = {k: v for k, v in pkg.items() if k != "seal"}
            if bl.sha256(bl.canonical(core)) != pkg["seal"]["package_hash"]:
                mismatches.append((p, "package_hash"))
        print("\n  stability gate: %d packages re-hashed, %d mismatches" % (len(paths), len(mismatches)))
        self.assertEqual(mismatches, [], "canonicalization instability must be exactly zero")


class HookSpool(unittest.TestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.state)

    def _events(self):
        run_hook(self.state, {"hook_event_name": "UserPromptSubmit", "session_id": "sess-1",
                              "prompt": SECRET, "cwd": "/secret/" + SECRET})
        run_hook(self.state, {"hook_event_name": "PreToolUse", "session_id": "sess-1",
                              "tool_name": "Bash", "tool_use_id": "toolu_1",
                              "tool_input": {"command": "echo " + SECRET}})
        run_hook(self.state, {"hook_event_name": "PostToolUse", "session_id": "sess-1",
                              "tool_name": "Bash", "tool_use_id": "toolu_1",
                              "tool_response": SECRET, "brand_new_field": SECRET})

    def _spool_file(self):
        return glob.glob(os.path.join(self.state, "actions", "spool", "*.jsonl"))[0]

    def test_records_chain_and_no_content(self):
        self._events()
        recs, cur, findings, stats = spool.read(self.state, {})
        self.assertEqual(len(recs), 3)
        self.assertEqual(findings, [])
        self.assertEqual([r["event"] for r in recs], ["prompt", "tool_call", "tool_result"])
        self.assertEqual(recs[2]["hook"]["unknown_fields"], ["brand_new_field"])
        with open(self._spool_file()) as f:
            self.assertNotIn(SECRET, f.read())
        self.assertNotIn("sess-1", open(self._spool_file()).read())
        again, _, findings2, _ = spool.read(self.state, cur)
        self.assertEqual((again, findings2), ([], []))

    def test_same_input_commits_identically_to_transcript(self):
        self._events()
        recs, _, _, _ = spool.read(self.state, {})
        key = al.load_key(self.state)
        c = recs[1]["content_commitments"]["tool_input"]
        self.assertEqual(c, al.commit(key, {"command": "echo " + SECRET}, "tool_input:toolu_1"))
        # one item opens without the key; the opening does not open a different item
        op = al.opening(key, {"command": "echo " + SECRET}, "tool_input:toolu_1")
        self.assertTrue(al.check_opening(c, op))
        self.assertNotIn(key.hex(), json.dumps(op))
        op_other = al.opening(key, {"command": "echo " + SECRET}, "tool_input:toolu_2")
        self.assertFalse(al.check_opening(c, op_other))

    def test_edit_breaks_chain_and_sealed_prefix(self):
        self._events()
        _, cur, _, _ = spool.read(self.state, {})
        p = self._spool_file()
        lines = open(p).read().splitlines()
        obj = json.loads(lines[1])
        obj["rec"]["tool"]["name"] = "Read"
        lines[1] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        open(p, "w").write("\n".join(lines) + "\n")
        _, _, findings, _ = spool.read(self.state, cur)
        kinds = sorted(f["finding"] for f in findings)
        self.assertIn("chain_break", kinds)
        self.assertIn("sealed_prefix_changed", kinds)

    def test_deleted_line_and_deleted_file(self):
        self._events()
        _, cur, _, _ = spool.read(self.state, {})
        p = self._spool_file()
        lines = open(p).read().splitlines()
        open(p, "w").write("\n".join([lines[0], lines[2]]) + "\n")
        _, _, findings, _ = spool.read(self.state, cur)
        self.assertIn("chain_break", [f["finding"] for f in findings])
        os.remove(p)
        _, _, findings, _ = spool.read(self.state, cur)
        self.assertEqual([f["finding"] for f in findings], ["spool_file_missing"])

    def test_bad_input_exits_zero_and_counts(self):
        r = run_hook(self.state, None, raw="{not json")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout, b"")
        self.assertEqual(spool.failures(self.state)["count"], 1)

    def test_hook_is_fast(self):
        t = time.time()
        for _ in range(5):
            run_hook(self.state, {"hook_event_name": "PreToolUse", "tool_name": "Read"})
        per = (time.time() - t) / 5
        print("\n  hook: %.0f ms per call including interpreter start" % (per * 1000))
        self.assertLess(per, 0.5)


class Transcripts(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.key = b"k" * 32
        os.makedirs(os.path.join(self.root, "proj"))
        self.f = os.path.join(self.root, "proj", "s1.jsonl")
        with open(self.f, "w") as fh:
            fh.write(tx_line("user", message={"role": "user", "content": SECRET}, promptId="p1"))
            fh.write(assistant("msg_1", "toolu_1"))
            fh.write(assistant("msg_1"))  # second block of the same message
            fh.write(tool_result("toolu_1"))

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_ingest_counts_and_no_content(self):
        recs, cur, findings, stats = ct.read(None, self.key, root=self.root)
        events = sorted(r["event"] for r in recs)
        self.assertEqual(events, ["model_turn", "prompt", "tool_call", "tool_result"])
        self.assertNotIn(SECRET, json.dumps(recs))
        self.assertNotIn("sess-1", json.dumps(recs))
        self.assertEqual(findings, [])
        a2 = ct.served_models(recs)
        self.assertEqual(a2, [{"requested": "claude-opus-5-5", "served": "claude-opus-5-5",
                               "turns": 1, "strings_differ": False}])

    def test_baseline_old_files_on_first_run(self):
        old = time.time() - 3 * 86400
        os.utime(self.f, (old, old))
        recs, cur, _, stats = ct.read(None, self.key, root=self.root)
        self.assertEqual((recs, stats["baselined_not_ingested"]), ([], 1))
        with open(self.f, "a") as fh:
            fh.write(assistant("msg_2", served="claude-sonnet-5-5"))
        recs, _, _, _ = ct.read(cur, self.key, root=self.root)
        self.assertEqual([(r["event"], r["model"]["served"]) for r in recs],
                         [("model_turn", "claude-sonnet-5-5")])
        self.assertTrue(ct.served_models(recs)[0]["strings_differ"])

    def test_increment_partial_line_and_rewrite(self):
        _, cur, _, _ = ct.read(None, self.key, root=self.root)
        with open(self.f, "a") as fh:
            fh.write('{"type": "assistant", "half')  # harness mid-write
        recs, cur2, findings, _ = ct.read(cur, self.key, root=self.root)
        self.assertEqual((recs, findings), ([], []))
        with open(self.f) as fh:
            data = fh.read().replace("msg_1", "msg_X", 1)
        with open(self.f, "w") as fh:
            fh.write(data)
        _, _, findings, _ = ct.read(cur2, self.key, root=self.root)
        self.assertEqual([f["finding"] for f in findings], ["sealed_prefix_changed"])

    def test_removal_is_a_retention_event(self):
        _, cur, _, _ = ct.read(None, self.key, root=self.root)
        os.remove(self.f)
        _, cur2, findings, _ = ct.read(cur, self.key, root=self.root)
        self.assertEqual(findings[0]["finding"], "transcripts_removed")
        self.assertEqual(cur2, {})


class Pairing(unittest.TestCase):
    def rec(self, source, tid, commit="hmac:a"):
        return {"source": source, "event": "tool_call", "correlation": {"tool_use_id": tid},
                "content_commitments": {"tool_input": commit}}

    def test_delta(self):
        recs = [self.rec("claude-code-hook", "t1"), self.rec("claude-code-transcript", "t1"),
                self.rec("claude-code-hook", "t2"), self.rec("claude-code-transcript", "t3"),
                self.rec("claude-code-hook", "t4", "hmac:x"),
                self.rec("claude-code-transcript", "t4", "hmac:y")]
        p = pairing.pair(recs, True)["pairing"]
        self.assertEqual((p["in_both"], p["hook_not_transcript"], p["transcript_not_hook"],
                          p["input_commitment_differs"]), (2, ["t2"], ["t3"], ["t4"]))

    def test_single_source_is_not_agreement(self):
        p = pairing.pair([], False)
        self.assertFalse(p["pairing"]["present"])
        self.assertTrue(p["derived"])


class McpClients(unittest.TestCase):
    def test_env_values_and_url_paths_never_recorded(self):
        d = tempfile.mkdtemp()
        try:
            cfg = os.path.join(d, "mcp.json")
            json.dump({"mcpServers": {
                "a": {"command": "npx", "args": ["-y", "pkg"], "env": {"API_TOKEN": SECRET}},
                "b": {"url": "https://mcp.example.com/sse?token=" + SECRET}}}, open(cfg, "w"))
            toml = os.path.join(d, "config.toml")
            open(toml, "w").write('[mcp_servers.c]\ncommand = "uvx"\nargs = ["srv"]\n')
            out = clients.mcp_clients([("t", cfg, "json", "mcpServers"),
                                       ("codex", toml, "toml", "mcp_servers"),
                                       ("missing", os.path.join(d, "nope.json"), "json", "mcpServers")])
            blob = json.dumps(out)
            self.assertNotIn(SECRET, blob)
            self.assertEqual(out[0]["servers"][0]["env_keys"], ["API_TOKEN"])
            self.assertEqual(out[0]["servers"][1]["remote"]["host"], "mcp.example.com")
            self.assertEqual(out[1]["servers"][0]["command_basename"], "uvx")
            self.assertFalse(out[2]["present"])
        finally:
            shutil.rmtree(d)


class FullCollect(unittest.TestCase):
    """End to end against a scratch state and a fixture transcript root."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.root = os.path.join(self.d, "transcripts")
        os.makedirs(os.path.join(self.root, "p"))
        with open(os.path.join(self.root, "p", "s.jsonl"), "w") as fh:
            fh.write(assistant("msg_1", "toolu_1"))
            fh.write(tool_result("toolu_1"))
        self.env = {**os.environ, "BEACON_TRANSCRIPT_ROOT": self.root,
                    "BEACON_OLLAMA_URL": "http://127.0.0.1:9"}
        self.env.pop("BEACON_PASSPHRASE", None)

    def tearDown(self):
        shutil.rmtree(self.d)

    def am(self, *a):
        return subprocess.run([sys.executable, os.path.join(HERE, "agentmode.py"),
                               "--state", os.path.join(self.d, "agent"),
                               "--home", os.path.join(self.d, "home")] + list(a),
                              env=self.env, capture_output=True, text=True, timeout=120)

    def test_collect_tick_verify_and_tamper(self):
        r = self.am("collect", "--reason", "test")
        self.assertEqual(r.returncode, 0, r.stderr)
        pkg_path = glob.glob(os.path.join(self.d, "agent", "packages", "*", "package.json"))[0]
        pkg = json.load(open(pkg_path))
        slots = [it["subcriterion"] for it in pkg["items"]]
        self.assertEqual(slots[-5:], ["agent-v0:H18", "agent-v0:H19", "agent-v0:H20",
                                      "agent-v0:H21", "agent-v0:H22"])
        h18 = pkg["items"][slots.index("agent-v0:H18")]
        # model_turn + tool_call + tool_result
        self.assertEqual(h18["observation"]["claim_sources"]["records"], 3)
        self.assertNotEqual(h18["source"]["raw_sha256"], pkg["items"][0]["source"]["raw_sha256"])
        self.assertEqual(self.am("verify-chain").returncode, 0)

        # nothing new: tick idles (unless a watched config surface moved meanwhile)
        r = self.am("tick")
        self.assertTrue("no change" in r.stdout or "reason=change" in r.stdout, r.stdout)
        # a new transcript line: tick seals with reason=actions
        with open(os.path.join(self.root, "p", "s.jsonl"), "a") as fh:
            fh.write(assistant("msg_2"))
        r = self.am("tick")
        self.assertIn("reason=", r.stdout)
        self.assertEqual(self.am("verify-chain").returncode, 0)

        # tamper one record inside the H18 segment blob: verification must fail
        blob = os.path.join(os.path.dirname(pkg_path), "blobs",
                            "sha256-" + h18["source"]["raw_sha256"] + ".json")
        data = json.load(open(blob))
        data["records"][0]["model"]["served"] = "claude-haiku-4-5"
        open(blob, "w").write(json.dumps(data))
        r = self.am("verify-chain")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("TAMPERED blob", r.stdout)

    def test_transcripts_off_by_default(self):
        """No operator-named root: no transcript is read, and H18 says why."""
        self.env.pop("BEACON_TRANSCRIPT_ROOT")
        self.env["HOME"] = self.d  # even the default root would be empty here
        os.makedirs(os.path.join(self.d, ".claude", "projects", "p"))
        shutil.copy(os.path.join(self.root, "p", "s.jsonl"),
                    os.path.join(self.d, ".claude", "projects", "p", "s.jsonl"))
        r = self.am("collect", "--reason", "default-off")
        self.assertEqual(r.returncode, 0, r.stderr)
        pkg_path = glob.glob(os.path.join(self.d, "agent", "packages", "*", "package.json"))[0]
        with open(pkg_path) as f:
            pkg = json.load(f)
        h18 = next(it for it in pkg["items"] if it["subcriterion"] == "agent-v0:H18")
        tx = h18["observation"]["transcript"]
        self.assertEqual((h18["observation"]["claim_sources"]["records"], tx["enabled"]), (0, False))
        self.assertIn("never read on defaults", tx["boundary"])
        self.assertIn("no change", self.am("tick").stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
