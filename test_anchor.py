#!/usr/bin/env python3
"""Offline tests for per-package anchoring (anchors.anchor_package and friends).

Run: python test_anchor.py

No network. The TSA and OTS calls are replaced with fakes so the claims under
test are the two invariants at the top of anchors.py:
  1. anchoring never blocks or undoes sealing (a sealed package on disk stays
     byte-identical and verifiable whatever the anchors do), and
  2. an unanchored package never looks anchored (every failure is recorded as
     pending/failed with the reason, never as confirmed).
The live path is exercised separately by `anchor.py stamp` against freetsa.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import contextlib

import beaconlib as bl
import anchors as an

fails = []


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def quiet(fn, *a, **k):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **k)
    return r, buf.getvalue()


def make_package(tmp):
    items = [{"subcriterion": "technology-v1:1.1a", "kind": "inventory",
              "observation": {"packages": 3}, "collected_utc": "2026-09-12T20:00:00+00:00"}]
    core = bl.build_package({"name": "t", "scope": "test", "collected_utc": "2026-09-12T20:00:00+00:00"},
                            {"name": "beacon-test", "version": "0"}, items)
    pkg = bl.seal_and_sign(core, sign=False, home=tmp)
    path = os.path.join(tmp, "package.json")
    with open(path, "w") as f:
        f.write(json.dumps(pkg, indent=2))
    return path, pkg


def sha(path):
    import hashlib
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    tmp = tempfile.mkdtemp(prefix="beacon-anchor-test-")
    try:
        path, pkg = make_package(tmp)
        before = sha(path)

        print("seal says unanchored until proven otherwise")
        check("seal.anchor is an object, not a stub string", isinstance(pkg["seal"]["anchor"], dict))
        check("seal.anchor.state == unanchored", pkg["seal"]["anchor"]["state"] == "unanchored")
        ok, _ = quiet(bl.verify_package, pkg)
        check("package verifies before any anchoring", ok)

        print("every anchor fails: package untouched, record honest")
        real_tsa, real_ots = an.tsa_timestamp, an.ots_stamp
        an.tsa_timestamp = lambda *a, **k: (_ for _ in ()).throw(ConnectionError("tsa down"))
        an.ots_stamp = lambda *a, **k: (None, {"kind": "opentimestamps", "authority": "bitcoin",
                                               "state": "pending", "error": "calendars refused",
                                               "submitted": an.utcnow()})
        rec = an.anchor_package(path, sealed_utc="2026-09-12T20:00:00+00:00", home=tmp)
        check("package bytes unchanged after failed anchoring", sha(path) == before)
        check("sidecar written", os.path.isfile(an.record_path(path)))
        states = {a["kind"]: a["state"] for a in rec["anchors"]}
        check("rfc3161 recorded pending with error, not confirmed",
              states.get("rfc3161") == "pending" and any(a.get("error") for a in rec["anchors"] if a["kind"] == "rfc3161"))
        check("opentimestamps recorded pending, not confirmed", states.get("opentimestamps") == "pending")
        check("rekor recorded pending with reason (gate off)",
              states.get("rekor-v2") == "pending" and any(a.get("reason") for a in rec["anchors"] if a["kind"] == "rekor-v2"))
        check("no .tsr written on failure", not os.path.isfile(path + ".tsr"))
        check("nothing in the record claims confirmed", "confirmed" not in states.values())
        vok, findings = an.verify_package_anchors(path)
        check("verify_package_anchors: ok (absence is truthful) and reports no token/proof",
              vok and any(m == "no token on disk" for _, m in findings))

        print("tsa succeeds, taken late: token written, late_anchor recorded")
        an.tsa_timestamp = lambda data, **k: (b"FAKE-TSR", {
            "kind": "rfc3161", "authority": "fake-tsa", "state": "confirmed",
            "observed_time": "2026-09-12T20:05:00", "serial": "0x1", "trust_anchor": "none"})
        rec = an.anchor_package(path, sealed_utc="2026-09-12T20:00:00+00:00", home=tmp, do_ots=False)
        r = [a for a in rec["anchors"] if a["kind"] == "rfc3161"][0]
        check("token file written", os.path.isfile(path + ".tsr"))
        check("state confirmed", r["state"] == "confirmed")
        check("late_anchor flagged when token time is 5 min after seal time", r.get("late_anchor") is True)
        check("seconds_after_seal recorded", r.get("seconds_after_seal") == 300.0)
        os.remove(path + ".tsr")
        an.tsa_timestamp = lambda data, **k: (b"FAKE-TSR", {
            "kind": "rfc3161", "authority": "fake-tsa", "state": "confirmed",
            "observed_time": "2026-09-12T20:00:02", "serial": "0x2", "trust_anchor": "none"})
        rec = an.anchor_package(path, sealed_utc="2026-09-12T20:00:00+00:00", home=tmp, do_ots=False)
        r = [a for a in rec["anchors"] if a["kind"] == "rfc3161"][0]
        check("token 2 s after seal is NOT flagged late (at-write anchoring)", not r.get("late_anchor") and r.get("seconds_after_seal") == 2.0)
        check("package bytes still unchanged", sha(path) == before)
        check("old opentimestamps pending entry preserved (not erased by a later run)",
              any(a["kind"] == "opentimestamps" and a["state"] == "pending" for a in rec["anchors"]))

        print("a second run does not re-timestamp an already-tokened package")
        calls = []
        an.tsa_timestamp = lambda data, **k: calls.append(1) or (b"X", {"kind": "rfc3161", "state": "confirmed", "observed_time": "2026-09-12T20:06:00", "authority": "fake"})
        an.anchor_package(path, home=tmp, do_ots=False)
        check("tsa not called again when .tsr exists", calls == [])

        print("sidecar refuses to describe a different package body")
        with open(path) as f:
            p2 = json.load(f)
        p2["seal"]["package_hash"] = "0" * 64
        with open(path, "w") as f:
            f.write(json.dumps(p2, indent=2))
        os.remove(path + ".tsr")
        an.tsa_timestamp = lambda *a, **k: (_ for _ in ()).throw(ConnectionError("tsa down"))
        rec = an.anchor_package(path, home=tmp, do_ots=False)
        check("record reset when package_hash changed", rec.get("note", "").startswith("previous sidecar discarded"))
        vok, findings = an.verify_package_anchors(path)
        check("verify reports ok on a fresh (empty) record", vok)

        an.tsa_timestamp, an.ots_stamp = real_tsa, real_ots

        print("anchor_after_write never raises")
        an.anchor_package = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        _, out = quiet(bl.anchor_after_write, path, enabled=True)
        check("failure printed, no exception", "FAILED to run" in out)
        _, out = quiet(bl.anchor_after_write, path, enabled=False)
        check("--no-anchor prints skipped", "skipped" in out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n%d checks failed" % len(fails))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
