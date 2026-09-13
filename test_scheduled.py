#!/usr/bin/env python3
"""Tests for scheduled mode (scheduled.py). Offline: jobs run with --no-anchor.

Run: python test_scheduled.py

Claims under test:
  - two runs of one job produce seq 1 and seq 2, and seq 2's sealed core carries
    prev_package_hash == seq 1's package_hash (the chain is under the seal);
  - verify passes on the intact series and FAILS when a package in the middle is
    altered (seal) or when the chain link is broken;
  - a failed job does not advance the chain and is recorded in runs.jsonl.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
fails = []


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def run(args, state):
    return subprocess.run([sys.executable, os.path.join(HERE, "scheduled.py"), "--state", state] + args,
                          capture_output=True, text=True)


def main():
    tmp = tempfile.mkdtemp(prefix="beacon-sched-test-")
    try:
        users = os.path.join(tmp, "users.json")
        with open(users, "w") as f:
            json.dump([{"user": "a@x", "mfa_enabled": True, "status": "active"},
                       {"user": "b@x", "mfa_enabled": False, "status": "active", "privileged": True}], f)
        cfg = {"series": "t", "sign": False,
               "jobs": [{"name": "idp", "mode": "export", "no_anchor": True,
                         "args": ["--export", users, "--source", "idp", "--subject", "t"]}]}
        cfg_path = os.path.join(tmp, "cfg.json")
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)
        state = os.path.join(tmp, "state")

        print("two runs chain under the seal")
        r1 = run(["run", "--config", cfg_path, "--reason", "t1"], state)
        r2 = run(["run", "--config", cfg_path, "--reason", "t2"], state)
        check("both runs exit 0", r1.returncode == 0 and r2.returncode == 0)
        jdir = os.path.join(state, "t", "idp")
        seqs = sorted(d for d in os.listdir(jdir) if d.startswith("seq"))
        check("seq0001 and seq0002 exist", [s[:7] for s in seqs] == ["seq0001", "seq0002"])
        p1 = json.load(open(os.path.join(jdir, seqs[0], "package.json")))
        p2 = json.load(open(os.path.join(jdir, seqs[1], "package.json")))
        c1 = p1["collector"].get("chain", {})
        c2 = p2["collector"].get("chain", {})
        check("seq 1 has no prev, sequence 1", c1.get("sequence") == 1 and c1.get("prev_package_hash") is None)
        check("seq 2 prev == seq 1 package_hash, inside the sealed core",
              c2.get("sequence") == 2 and c2.get("prev_package_hash") == p1["seal"]["package_hash"])
        chain = json.load(open(os.path.join(jdir, "chain.json")))
        check("chain.json head == seq 2 hash", chain["last_package_hash"] == p2["seal"]["package_hash"])
        v = run(["verify"], state)
        check("verify: SERIES OK", v.returncode == 0 and "SERIES OK" in v.stdout)
        s = run(["status"], state)
        check("status lists the job at seq 2", "seq 2" in s.stdout)

        print("tamper in the middle is caught")
        path1 = os.path.join(jdir, seqs[0], "package.json")
        d = json.load(open(path1))
        d["items"][0]["observation"]["mfa"]["coverage_fraction"] = 1.0
        json.dump(d, open(path1, "w"))
        v = run(["verify"], state)
        check("verify fails on an altered seal", v.returncode == 1 and "seal=FAIL" in v.stdout)
        # restore, then break the link instead
        json.dump(p1, open(path1, "w"), indent=2)
        v = run(["verify"], state)
        check("restored series verifies again", v.returncode == 0)
        d = json.load(open(path1))
        d["subject"]["name"] = "t"          # no-op edit, but reseal by hand is not possible; so break the link on seq 2
        path2 = os.path.join(jdir, seqs[1], "package.json")
        # A forged seq 2 with a different prev would need a new seal; simulate a chain
        # break by removing seq 1 (the verifier then expects prev None for the first
        # remaining package and sees seq 2's prev pointing at a hash that is gone).
        shutil.rmtree(os.path.join(jdir, seqs[0]))
        v = run(["verify"], state)
        check("verify reports a BROKEN chain when the predecessor is missing", v.returncode == 1 and "chain=BROKEN" in v.stdout)

        print("a failed job does not advance the chain")
        cfg["jobs"].append({"name": "bad", "mode": "export", "no_anchor": True,
                            "args": ["--export", "/nonexistent.json", "--source", "idp", "--subject", "t"]})
        json.dump(cfg, open(cfg_path, "w"))
        r3 = run(["run", "--config", cfg_path, "--reason", "t3"], state)
        check("run exits 1 when a job fails", r3.returncode == 1)
        check("good job advanced to seq 3", json.load(open(os.path.join(jdir, "chain.json")))["sequence"] == 3)
        check("bad job has no chain", not os.path.isfile(os.path.join(state, "t", "bad", "chain.json")))
        last = open(os.path.join(state, "t", "runs.jsonl")).read().strip().splitlines()[-1]
        rec = json.loads(last)
        check("runs.jsonl records the failure", any(not j.get("ok") and j["job"] == "bad" for j in rec["jobs"]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d checks failed" % len(fails))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
