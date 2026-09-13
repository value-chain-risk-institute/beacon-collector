#!/usr/bin/env python3
"""scheduled.py, Beacon Collector scheduled mode for an organization (v0.1, 2026-09-12).

Posture as a series, not a snapshot (SPEC 0.7), for the ORG collector rather than
the household agent. Runs a configured list of collections on a timer, keeps every
sealed package under an org-owned state directory, chains each package to the
previous one INSIDE the sealed core (beaconlib.build_package reads
BEACON_CHAIN_SEQ / BEACON_CHAIN_PREV / BEACON_CHAIN_SERIES), anchors at write time
through the modes themselves, and upgrades pending OpenTimestamps proofs on later
runs. Nothing leaves the machine unless a job says so; the org owns the history.

  scheduled.py run     --config beacon-schedule.json [--state ~/.beacon/org] [--reason timer]
  scheduled.py status  [--state ~/.beacon/org]
  scheduled.py verify  [--state ~/.beacon/org]        # every package seal + chain + anchors

Config (JSON):
  {
    "series": "acme-prod",                    # name of this evidence series
    "home": "~/.beacon",                       # enrollment home (for --sign)
    "sign": true,
    "jobs": [
      {"name": "hosts",  "mode": "scanner",  "args": ["--target", "/", "--subject", "acme", "--box", "web-1"]},
      {"name": "idp",    "mode": "export",   "args": ["--export", "/srv/exports/okta-users.json", "--source", "idp", "--subject", "acme"]},
      {"name": "soc2",   "mode": "document", "args": ["--doc", "/srv/docs/soc2-2026.txt", "--doc-type", "soc2", "--subject", "acme"]}
    ]
  }

Layout under --state:
  <series>/<job>/seq0001-<utc>/package.json (+ .tsr .ots .anchors.json, blobs/)
  <series>/<job>/chain.json      last sequence + last package_hash for that job
  <series>/runs.jsonl            one line per run: when, why, what sealed, what failed

Deploy templates in deploy/ (launchd, systemd timer, cron). Same invariants as the
rest of the tree: never scores, anchoring never blocks sealing, absence is recorded
as absence.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
H = os.path.expanduser
DEFAULT_STATE = "~/.beacon/org"

MODES = {
    "scanner": ("collector.py", "collect"),
    "document": ("docs.py", "collect"),
    "export": ("exportmode.py", "collect"),
}
VERIFIERS = {
    "scanner": "collector.py",
    "document": "docs.py",
    "export": "exportmode.py",
    "merge": "merge.py",
}


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


def append_jsonl(path, obj):
    with open(path, "a") as f:
        f.write(json.dumps(obj) + "\n")


def run_job(cfg, job, state, reason):
    """Run one configured collection as a subprocess of the mode's own CLI, with
    the chain link handed over in the environment. Returns a run record."""
    series = cfg.get("series", "default")
    job_dir = os.path.join(state, series, job["name"])
    os.makedirs(job_dir, exist_ok=True)
    chain_path = os.path.join(job_dir, "chain.json")
    chain = load_json(chain_path, {"sequence": 0, "last_package_hash": None})
    seq = chain["sequence"] + 1
    out_dir = os.path.join(job_dir, "seq%04d-%s" % (seq, stamp()))

    mode = job["mode"]
    if mode not in MODES:
        return {"job": job["name"], "ok": False, "error": "unknown mode %r" % mode}
    script, verb = MODES[mode]
    cmd = [sys.executable, os.path.join(HERE, script), verb] + list(job.get("args", [])) + ["--out-dir", out_dir]
    if cfg.get("sign") and "--sign" not in cmd:
        cmd += ["--sign", "--home", H(cfg.get("home", "~/.beacon"))]
    if job.get("no_anchor"):
        cmd.append("--no-anchor")

    env = dict(os.environ)
    env["BEACON_CHAIN_SEQ"] = str(seq)
    env["BEACON_CHAIN_PREV"] = chain.get("last_package_hash") or ""
    env["BEACON_CHAIN_SERIES"] = series

    started = utcnow()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env,
                           timeout=int(job.get("timeout_seconds", 1800)))
    except subprocess.TimeoutExpired:
        return {"job": job["name"], "ok": False, "sequence": seq, "started": started,
                "error": "timed out after %ss" % job.get("timeout_seconds", 1800), "out_dir": out_dir}

    pkg_path = os.path.join(out_dir, "package.json")
    pkg = load_json(pkg_path)
    rec = {"job": job["name"], "mode": mode, "sequence": seq, "started": started,
           "finished": utcnow(), "out_dir": out_dir, "exit": r.returncode,
           "ok": r.returncode == 0 and pkg is not None}
    if rec["ok"]:
        rec["package_hash"] = pkg["seal"]["package_hash"]
        rec["prev_package_hash"] = chain.get("last_package_hash")
        anchors = load_json(pkg_path + ".anchors.json", {}).get("anchors", [])
        rec["anchors"] = {a.get("kind"): a.get("state") for a in anchors}
        chain = {"sequence": seq, "last_package_hash": rec["package_hash"],
                 "last_out_dir": out_dir, "updated": rec["finished"]}
        save_json(chain_path, chain)
    else:
        # A failed run does not advance the chain. Record the failure loudly; the
        # gap in sequence numbers is the honest record of a missed collection.
        rec["stderr_tail"] = (r.stderr or "").strip()[-600:]
        rec["stdout_tail"] = (r.stdout or "").strip()[-300:]
    return rec


def iter_packages(state, series=None):
    for root, dirs, files in os.walk(H(state)):
        if "package.json" in files and os.path.basename(root).startswith("seq"):
            if series and series not in root.split(os.sep):
                continue
            yield os.path.join(root, "package.json")


def upgrade_pending(state):
    """Later runs pull down Bitcoin paths for proofs still marked submitted."""
    sys.path.insert(0, HERE)
    import anchors as an
    done = pending = 0
    for pkg_path in iter_packages(state):
        rec = load_json(pkg_path + ".anchors.json")
        if not rec:
            continue
        for a in rec.get("anchors", []):
            if a.get("kind") == "opentimestamps" and a.get("state") == "submitted":
                ok, _ = an.upgrade_package_anchors(pkg_path)
                done += 1 if ok else 0
                pending += 0 if ok else 1
    return done, pending


def cmd_run(args):
    cfg = load_json(H(args.config))
    if not cfg or not cfg.get("jobs"):
        sys.exit("config %s missing or has no jobs" % args.config)
    state = H(args.state)
    os.makedirs(os.path.join(state, cfg.get("series", "default")), exist_ok=True)
    runs_path = os.path.join(state, cfg.get("series", "default"), "runs.jsonl")

    run = {"run_utc": utcnow(), "reason": args.reason, "jobs": []}
    for job in cfg["jobs"]:
        rec = run_job(cfg, job, state, args.reason)
        run["jobs"].append(rec)
        line = "%-12s %s" % (job["name"], "sealed seq %s %s" % (rec.get("sequence"), (rec.get("package_hash") or "")[:16])
                              if rec.get("ok") else "FAILED: %s" % (rec.get("error") or rec.get("stderr_tail", "")[-200:]))
        print(line)
        if rec.get("ok") and rec.get("anchors"):
            print("             anchors: " + ", ".join("%s=%s" % kv for kv in rec["anchors"].items()))

    try:
        done, pending = upgrade_pending(state)
        run["ots_upgrade"] = {"confirmed_now": done, "still_pending": pending}
        if done or pending:
            print("ots upgrade pass: %d confirmed, %d still pending" % (done, pending))
    except Exception as e:  # never let the upgrade pass fail the run
        run["ots_upgrade"] = {"error": "%s: %s" % (type(e).__name__, str(e)[:120])}

    append_jsonl(runs_path, run)
    failed = [j for j in run["jobs"] if not j.get("ok")]
    sys.exit(1 if failed else 0)


def cmd_status(args):
    state = H(args.state)
    if not os.path.isdir(state):
        sys.exit("no state at %s" % state)
    for series in sorted(os.listdir(state)):
        sdir = os.path.join(state, series)
        if not os.path.isdir(sdir):
            continue
        print("series %s" % series)
        runs = os.path.join(sdir, "runs.jsonl")
        last = None
        if os.path.isfile(runs):
            with open(runs) as f:
                for line in f:
                    last = line
        if last:
            r = json.loads(last)
            print("  last run %s (%s): %d job(s), %d failed" % (
                r["run_utc"], r.get("reason"), len(r["jobs"]), sum(1 for j in r["jobs"] if not j.get("ok"))))
        for job in sorted(os.listdir(sdir)):
            jdir = os.path.join(sdir, job)
            chain = load_json(os.path.join(jdir, "chain.json"))
            if chain:
                pending = 0
                for pkg_path in iter_packages(jdir):
                    rec = load_json(pkg_path + ".anchors.json", {})
                    pending += sum(1 for a in rec.get("anchors", []) if a.get("kind") == "opentimestamps" and a.get("state") == "submitted")
                print("  %-12s seq %s  last %s  head %s  ots pending %d" % (
                    job, chain["sequence"], chain.get("updated", "")[:19], (chain.get("last_package_hash") or "")[:16], pending))


def cmd_verify(args):
    """Every package: seal verifies via its own mode's verifier, chain links agree,
    anchors verify offline. Exit 1 on any failure; absence of anchors is reported,
    not failed."""
    sys.path.insert(0, HERE)
    import anchors as an
    state = H(args.state)
    ok = True
    n = 0
    for series in sorted(os.listdir(state)):
        sdir = os.path.join(state, series)
        if not os.path.isdir(sdir):
            continue
        for job in sorted(os.listdir(sdir)):
            jdir = os.path.join(sdir, job)
            if not os.path.isdir(jdir):
                continue
            pkgs = sorted(iter_packages(jdir))
            prev_hash = None
            for pkg_path in pkgs:
                n += 1
                pkg = load_json(pkg_path)
                mode = (pkg.get("collector", {}).get("name", "") if pkg else "")
                verifier = "collector.py"
                if "document" in mode:
                    verifier = "docs.py"
                elif "export" in mode:
                    verifier = "exportmode.py"
                elif "merge" in mode:
                    verifier = "merge.py"
                r = subprocess.run([sys.executable, os.path.join(HERE, verifier), "verify", pkg_path],
                                   capture_output=True, text=True)
                seal_ok = r.returncode == 0
                chain = (pkg or {}).get("collector", {}).get("chain") or {}
                link_ok = (chain.get("prev_package_hash") or None) == prev_hash
                a_ok, findings = an.verify_package_anchors(pkg_path)
                flag = "ok " if (seal_ok and link_ok and a_ok) else "BAD"
                print("%s %s/%s %s seal=%s chain=%s anchors=%s" % (
                    flag, series, job, os.path.basename(os.path.dirname(pkg_path)),
                    "ok" if seal_ok else "FAIL", "ok" if link_ok else "BROKEN",
                    "ok" if a_ok else "PROBLEM"))
                if not link_ok:
                    print("     expected prev %s, sealed prev %s" % (
                        (prev_hash or "none")[:16], (chain.get("prev_package_hash") or "none")[:16]))
                ok = ok and seal_ok and link_ok and a_ok
                prev_hash = (pkg or {}).get("seal", {}).get("package_hash")
    print("\nSERIES %s: %d package(s) checked" % ("OK" if ok else "PROBLEM", n))
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default=DEFAULT_STATE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--config", required=True)
    r.add_argument("--reason", default="timer")
    sub.add_parser("status")
    sub.add_parser("verify")
    a = ap.parse_args()
    {"run": cmd_run, "status": cmd_status, "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    main()
