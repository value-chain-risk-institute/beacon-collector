#!/usr/bin/env python3
"""
test_aiusage.py: AI service use from network logs. Proves the counts, the three
input formats, and the minimisation promises (no client address, no non-AI
domain, no full AI hostname, small counts suppressed), plus tamper detection.

Run: ~/.beacon/venv/bin/python test_aiusage.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import aiusage  # noqa: E402

ZEEK_DNS = "\n".join([
    "#separator \\x09",
    "#path\tdns",
    "#fields\tts\tuid\tid.orig_h\tid.resp_h\tquery",
    "1760270000.1\tC1\t10.0.0.11\t10.0.0.1\tchatgpt.com",
    "1760270001.2\tC2\t10.0.0.12\t10.0.0.1\tchatgpt.com",
    "1760270002.3\tC3\t10.0.0.13\t10.0.0.1\tab.chatgpt.com",
    "1760270003.4\tC4\t10.0.0.11\t10.0.0.1\tsecret-bank-portal.example",
    "1760270004.5\tC5\t10.0.0.14\t10.0.0.1\ttenant-acme123.claude.ai",
    "1760270005.6\tC6\t10.0.0.11\t10.0.0.1\tnotchatgpt.com",
    "garbage line with wrong field count",
]) + "\n"

ECS_NDJSON = "\n".join([
    json.dumps({"@timestamp": "2026-10-12T12:00:00Z", "source": {"ip": "10.0.1.5"},
                "tls": {"client": {"server_name": "api.anthropic.com"}}}),
    json.dumps({"@timestamp": "2026-10-12T12:00:01Z", "source": {"ip": "10.0.1.6"},
                "tls": {"client": {"server_name": "api.anthropic.com"}}}),
    json.dumps({"@timestamp": "2026-10-12T12:00:02Z", "source": {"ip": "10.0.1.7"},
                "tls": {"client": {"server_name": "api.anthropic.com"}}}),
    json.dumps({"@timestamp": "2026-10-12T12:00:03Z", "source": {"ip": "10.0.1.7"},
                "url": {"domain": "www.example.org"}}),
    "{not json",
]) + "\n"

PROXY_CSV = "Timestamp,Src_IP,Host\n2026-10-12T13:00:00Z,10.0.2.9,gemini.google.com\n" \
            "2026-10-12T13:00:05Z,10.0.2.9,mail.google.com\n"


class Counts(unittest.TestCase):
    def setUp(self):
        _, self.index = aiusage.load_catalog()

    def obs(self, text, fmt="auto", suppress=3):
        return aiusage.observe([(text, fmt)], self.index, suppress)["ai_service_use"]

    def test_zeek_counts_suffix_match_and_suppression(self):
        a = self.obs(ZEEK_DNS)
        by = {s["service"]: s for s in a["services"]}
        self.assertEqual(by["ChatGPT"]["events"], 3)        # subdomain counts, lookalike does not
        self.assertEqual(by["ChatGPT"]["distinct_clients"], 3)
        self.assertIsNone(by["Claude"]["distinct_clients"])  # one client: suppressed
        self.assertNotIn("notchatgpt.com", json.dumps(a))
        self.assertEqual(a["totals"]["lines_unparseable"], 1)
        self.assertEqual(a["log_types"], ["dns"])

    def test_ecs_ndjson(self):
        a = self.obs(ECS_NDJSON)
        self.assertEqual([(s["service"], s["events"], s["distinct_clients"]) for s in a["services"]],
                         [("Anthropic API", 3, 3)])
        self.assertEqual(a["window"]["first"], "2026-10-12T12:00:00Z")
        self.assertEqual(a["totals"]["lines_unparseable"], 1)

    def test_proxy_csv(self):
        a = self.obs(PROXY_CSV)
        self.assertEqual([s["service"] for s in a["services"]], ["Gemini"])

    def test_minimisation(self):
        blob = json.dumps(self.obs(ZEEK_DNS + "") ) + json.dumps(self.obs(ECS_NDJSON))
        for leak in ("10.0.0.11", "10.0.1.5", "secret-bank-portal", "www.example.org",
                     "tenant-acme123", "ab.chatgpt.com"):
            self.assertNotIn(leak, blob, leak)


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.log = os.path.join(self.d, "dns.log")
        with open(self.log, "w") as f:
            f.write(ZEEK_DNS)

    def tearDown(self):
        shutil.rmtree(self.d)

    def run_cli(self, *a):
        return subprocess.run([sys.executable, os.path.join(HERE, "aiusage.py")] + list(a),
                              capture_output=True, text=True, timeout=60)

    def test_collect_verify_tamper_and_no_raw_log(self):
        out = os.path.join(self.d, "out")
        r = self.run_cli("collect", "--log", self.log, "--subject", "test-org", "--out-dir", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        pkg_path = os.path.join(out, "package.json")
        self.assertEqual(self.run_cli("verify", pkg_path).returncode, 0)
        everything = ""
        for root, _, files in os.walk(out):
            for fn in files:
                with open(os.path.join(root, fn)) as f:
                    everything += f.read()
        self.assertNotIn("10.0.0.11", everything)
        self.assertNotIn("secret-bank-portal", everything)
        with open(pkg_path) as f:
            pkg = json.load(f)
        ref = pkg["items"][0]["observation"]["ai_service_use"]["inputs"][0]
        self.assertFalse(ref["retained"])
        # tamper: inflate a count in the sealed package
        pkg["items"][0]["observation"]["ai_service_use"]["services"][0]["events"] += 1
        with open(pkg_path, "w") as f:
            json.dump(pkg, f)
        self.assertNotEqual(self.run_cli("verify", pkg_path).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
