#!/usr/bin/env python3
"""Tests for ui.py. Run: ~/.beacon/venv/bin/python test_ui.py

The console's job is mostly refusal: a page that renders is easy, a page that
refuses the wrong caller is the part that is invisible unless each refusal is
asserted. Fixture packages are built in a temp directory by the real sealing
code (beaconlib.seal_and_sign with a throwaway enrolled key); nothing under
~/.beacon is read or written.
"""
import copy
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import beaconlib as bl
import ui

HERE = os.path.dirname(os.path.abspath(__file__))
HOSTILE = '<script>alert("x")</script><img src=x onerror=alert(1)>&\''
PASS = "test-ui-passphrase"


def _item(slot, layer, element, obs, expected):
    it = {"subcriterion": slot, "layer": layer, "element": element, "mode": "agent-continuous",
          "observation": obs, "context": [], "completeness": bl.completeness(obs, expected),
          "freshness": {"collected_utc": "2026-10-12T00:00:00+00:00", "evidence_age_seconds": 0}}
    it["item_sha256"] = bl.hash_item(it)
    return it


def build_fixture(root):
    home = os.path.join(root, "home")
    state = os.path.join(root, "agent")
    env = dict(os.environ, BEACON_PASSPHRASE=PASS)
    subprocess.run([sys.executable, os.path.join(HERE, "enroll.py"), "init", "--collector-id", "ui-test",
                    "--token", "t", "--home", home], env=env, check=True, capture_output=True)
    os.environ["BEACON_PASSPHRASE"] = PASS
    prev = None
    names = []
    for seq, note in ((1, "first"), (2, HOSTILE), (3, "third")):
        items = [
            _item("agent-v0:A1", "model", "model-identity-per-endpoint",
                  {"endpoints": {"present": False, "note": "no endpoint " + note},
                   "local_inference": {"present": True}, "note": note},
                  ["endpoints", "local_inference"]),
            _item("agent-v0:H18", "household", "action-ledger",
                  {"actions": {"present": True}}, ["actions"]),
        ]
        core = bl.build_package({"name": "fixture " + note, "collected_utc": "2026-10-12T00:0%d:00+00:00" % seq},
                                {"name": "beacon-agentmode", "version": "test"}, items)
        core["chain"] = {"sequence": seq, "prev_package_hash": prev, "reason": "heartbeat",
                         "changed_surfaces": []}
        pkg = bl.seal_and_sign(core, sign=True, home=home)
        name = "seq%04d-2026-10-12T000%d" % (seq, seq)
        d = os.path.join(state, "packages", name)
        os.makedirs(d)
        with open(os.path.join(d, "package.json"), "w") as f:
            json.dump(pkg, f, indent=2)
        prev = pkg["seal"]["package_hash"]
        names.append(name)
    del os.environ["BEACON_PASSPHRASE"]

    # a tampered copy of seq 2: one observation value edited after sealing
    src = os.path.join(state, "packages", names[1], "package.json")
    with open(src) as f:
        pkg = json.load(f)
    bad = copy.deepcopy(pkg)
    bad["items"][0]["observation"]["local_inference"]["present"] = False
    bad["chain"]["sequence"] = 4
    tname = "seq0004-2026-10-12T0004"
    os.makedirs(os.path.join(state, "packages", tname))
    with open(os.path.join(state, "packages", tname, "package.json"), "w") as f:
        json.dump(bad, f, indent=2)

    with open(os.path.join(state, "state.json"), "w") as f:
        json.dump({"sequence": 3, "last_package_hash": prev, "last_seal_epoch": time.time() - 60,
                   "last_seal_utc": "2026-10-12T00:03:00+00:00", "last_reason": "heartbeat"}, f)
    return home, state, names, tname


class UITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="beacon-ui-test-")
        cls.home, cls.state, cls.names, cls.tampered = build_fixture(cls.tmp)
        cls.exports = os.path.join(cls.tmp, "exports")
        cls.srv, cls.app = ui.make_server(cls.state, cls.home, cls.exports, port=0)
        cls.thread = threading.Thread(target=cls.srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        cls.thread.start()
        cls.port = cls.app.port
        cls.host = "127.0.0.1:%d" % cls.port
        st, hdr, _ = cls.req("GET", "/?token=" + cls.app.token)
        assert st == 303, st
        cls.set_cookie = hdr.get("Set-Cookie", "")
        cls.cookie = cls.set_cookie.split(";")[0]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def req(cls, method, path, headers=None, body=None, host=None, cookie=True):
        c = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=30)
        h = {"Host": host or "127.0.0.1:%d" % cls.port}
        if cookie and getattr(cls, "cookie", None):
            h["Cookie"] = cls.cookie
        h.update(headers or {})
        c.putrequest(method, path, skip_host=True)
        for k, v in h.items():
            c.putheader(k, v)
        data = body.encode() if body else None
        if data is not None:
            c.putheader("Content-Type", "application/x-www-form-urlencoded")
            c.putheader("Content-Length", str(len(data)))
        c.endheaders(data)
        r = c.getresponse()
        out = r.read().decode("utf-8", "replace")
        hdr = dict(r.getheaders())
        c.close()
        return r.status, hdr, out

    def csrf(self):
        st, _, body = self.req("GET", "/export")
        self.assertEqual(st, 200)
        return re.search(r'name="csrf" value="([^"]+)"', body).group(1)

    def post_export(self, csrf, origin=None, package=None, framework="cra-annex-i"):
        import urllib.parse
        body = urllib.parse.urlencode({"csrf": csrf, "package": package or self.names[-1], "framework": framework})
        h = {"Origin": origin if origin is not None else "http://" + self.host}
        if origin == "":
            h = {}
        return self.req("POST", "/export", headers=h, body=body)

    # ---- refusals
    def test_missing_token_refused(self):
        st, _, body = self.req("GET", "/", cookie=False)
        self.assertEqual(st, 403)
        self.assertNotIn("Status", body)

    def test_bad_token_refused(self):
        st, hdr, _ = self.req("GET", "/?token=nope", cookie=False)
        self.assertEqual(st, 403)
        self.assertNotIn("Set-Cookie", hdr)

    def test_bad_cookie_refused(self):
        st, _, _ = self.req("GET", "/", headers={"Cookie": "beacon_ui_%d=forged" % self.port}, cookie=False)
        self.assertEqual(st, 403)

    def test_cookie_flags(self):
        self.assertIn("HttpOnly", self.set_cookie)
        self.assertIn("SameSite=Strict", self.set_cookie)

    def test_wrong_host_refused(self):
        st, _, _ = self.req("GET", "/", host="evil.example:%d" % self.port)
        self.assertEqual(st, 400)
        st, _, _ = self.req("GET", "/", host="127.0.0.1:1")
        self.assertEqual(st, 400)
        st, _, _ = self.req("GET", "/", host="localhost:%d" % self.port)
        self.assertEqual(st, 200)

    def test_cross_origin_post_refused(self):
        before = os.listdir(self.exports) if os.path.isdir(self.exports) else []
        st, _, _ = self.post_export(self.csrf(), origin="http://evil.example")
        self.assertEqual(st, 403)
        st, _, _ = self.post_export(self.csrf(), origin="")  # no Origin at all
        self.assertEqual(st, 403)
        after = os.listdir(self.exports) if os.path.isdir(self.exports) else []
        self.assertEqual(before, after)

    def test_csrf_mismatch_refused(self):
        st, _, _ = self.post_export("wrong-token")
        self.assertEqual(st, 403)

    def test_remote_bind_refused(self):
        with self.assertRaises(ui.RefusedBind):
            ui.make_server(self.state, self.home, self.exports, port=0, bind="0.0.0.0")

    def test_package_name_traversal_refused(self):
        st, _, _ = self.req("GET", "/package/..%2F..%2Fstate.json")
        self.assertEqual(st, 404)
        st, _, _ = self.req("GET", "/package/../state.json")
        self.assertEqual(st, 404)

    def test_no_cors_and_security_headers(self):
        st, hdr, _ = self.req("GET", "/", headers={"Origin": "http://evil.example"})
        self.assertEqual(st, 200)
        self.assertFalse(any(k.lower().startswith("access-control") for k in hdr))
        self.assertIn("default-src 'self'", hdr["Content-Security-Policy"])
        self.assertIn("script-src 'none'", hdr["Content-Security-Policy"])
        self.assertEqual(hdr["X-Frame-Options"], "DENY")
        self.assertEqual(hdr["Referrer-Policy"], "no-referrer")

    # ---- screens
    def test_status_renders(self):
        st, _, body = self.req("GET", "/")
        self.assertEqual(st, 200)
        self.assertIn("<h1>Status</h1>", body)
        with open(os.path.join(self.state, "state.json")) as f:
            self.assertIn(json.load(f)["last_package_hash"], body)
        self.assertIn("heartbeat due", body)
        self.assertIn("max gap", body)
        self.assertIn("signing", body)

    def test_sources_shows_absent_and_h_elements(self):
        st, _, body = self.req("GET", "/sources")
        self.assertEqual(st, 200)
        self.assertIn("agent-v0:H18", body)
        self.assertIn("agent-v0:G17", body)          # missing from fixture, shown as absent
        self.assertIn("element not present in this package at all", body)
        self.assertIn('class="pill absent"', body)

    def test_timeline_renders_with_style_hash(self):
        st, hdr, body = self.req("GET", "/timeline?n=3")
        self.assertEqual(st, 200)
        self.assertIn("Change ribbon", body)
        self.assertIn("'sha256-", hdr["Content-Security-Policy"])

    def test_packages_list(self):
        st, _, body = self.req("GET", "/packages")
        self.assertEqual(st, 200)
        for n in self.names:
            self.assertIn(n, body)

    def test_verify_untouched_is_verified(self):
        st, _, body = self.req("GET", "/package/%s?verify=1" % self.names[0])
        self.assertEqual(st, 200)
        self.assertIn('class="verdict verified"', body)
        self.assertNotIn('class="verdict tampered"', body)
        self.assertNotIn('class="verdict unproven"', body)

    def test_verify_tampered_is_tampered(self):
        st, _, body = self.req("GET", "/package/%s?verify=1" % self.tampered)
        self.assertEqual(st, 200)
        self.assertIn('class="verdict tampered"', body)
        self.assertNotIn('class="verdict verified"', body)

    def test_verify_unproven_is_not_collapsed(self):
        saved = bl.HAVE_CRYPTO
        env = os.environ.pop("BEACON_ALLOW_UNVERIFIED", None)
        bl.HAVE_CRYPTO = False
        try:
            state, out = ui.verify_state(os.path.join(self.state, "packages", self.names[0], "package.json"),
                                         self.home)
        finally:
            bl.HAVE_CRYPTO = saved
            if env is not None:
                os.environ["BEACON_ALLOW_UNVERIFIED"] = env
        self.assertEqual(state, ui.UNPROVEN, out)

    def test_hostile_string_escaped(self):
        for path in ("/sources", "/package/%s" % self.names[1]):
            st, _, body = self.req("GET", path)
            self.assertEqual(st, 200)
            self.assertNotIn("<script>alert", body, path)
            self.assertNotIn("<img src=x", body, path)
            self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", body, path)

    def test_export_writes_new_bundle(self):
        st, _, body = self.post_export(self.csrf(), package=self.names[0])
        self.assertEqual(st, 200, body)
        dirs = os.listdir(self.exports)
        self.assertTrue(dirs)
        newest = os.path.join(self.exports, sorted(dirs)[-1])
        for f in ("package.json", "coverage.json", "coverage.md", "index.html", "README.md"):
            self.assertTrue(os.path.isfile(os.path.join(newest, f)), f)

    def test_export_refuses_tampered(self):
        before = sorted(os.listdir(self.exports)) if os.path.isdir(self.exports) else []
        st, _, body = self.post_export(self.csrf(), package=self.tampered)
        self.assertEqual(st, 409)
        self.assertIn("Refusing to export", body)
        after = sorted(os.listdir(self.exports)) if os.path.isdir(self.exports) else []
        self.assertEqual(before, after)

    def test_get_cannot_export(self):
        before = sorted(os.listdir(self.exports)) if os.path.isdir(self.exports) else []
        self.req("GET", "/export?package=%s&framework=cra-annex-i" % self.names[0])
        after = sorted(os.listdir(self.exports)) if os.path.isdir(self.exports) else []
        self.assertEqual(before, after)


class IdleTest(unittest.TestCase):
    def test_idle_timeout_exits(self):
        tmp = tempfile.mkdtemp(prefix="beacon-ui-idle-")
        try:
            srv, app = ui.make_server(os.path.join(tmp, "agent"), os.path.join(tmp, "home"),
                                      os.path.join(tmp, "exports"), port=0, idle_seconds=1)
            ui.start_idle_watch(srv, app)
            t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
            t.start()
            t.join(timeout=10)
            self.assertFalse(t.is_alive(), "server still running after idle timeout")
            srv.server_close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
