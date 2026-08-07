#!/usr/bin/env python3
"""
collector.py, BeaconScore Collector v0.2: Trivy LIVE, multi-item packages.

Evolves spike 0 (beacon.py, kept intact for provenance) to the full
vcri.beacon.evidence-package/v0 shape from EVIDENCE-SCHEMA-and-source-map-v0.1.md:

  subject / collector / items[] / seal
  ONE live Trivy pass -> THREE evidence items:
    technology-v1:1.1a  inventory + SBOM + signing      (mode: scanner)
    technology-v1:4.4a  vulnerability + patch findings  (mode: scanner)
    technology-v1:1.1b  config baseline (misconfig)     (mode: scanner)

Invariants (Joshua's calls, 2026-07-28):
  - The collector NEVER rates. Observations are facts; leveling is the
    scorer's / CRC's job, downstream, from the sealed package.
  - Each item carries item_sha256; the package carries seal.package_hash.
    Editing ANY field of ANY item, or any package field, breaks verify.
  - context = subject CLAIMS: sealed, verified:false, epistemic subject_claim.
    The open self-scorer ignores them; a human CRC assessor may weigh them.
  - Freshness + completeness are evidence-QUALITY metadata, not judgments.
  - Raw tool output is stored as a hashed blob; artifact_ref binds it.

Usage:
  collector.py collect --target PATH [--subject NAME] [--scope TEXT]
                       [--note TEXT] [--out-dir DIR]
  collector.py verify PACKAGE.json [--blobs DIR]
"""
import argparse
import json
import os
import platform
import subprocess
import sys

VERSION = "0.3.0"

import beaconlib as bl
from beaconlib import canonical, sha256, utcnow, completeness

EXPECTED = {
    "technology-v1:1.1a": ["package_inventory", "sbom", "signed_attestation"],
    "technology-v1:4.4a": ["vulnerability_findings", "fix_availability"],
    "technology-v1:1.1b": ["misconfig_findings", "checks_evaluated"],
}


# ---------------- Trivy run + raw blob ----------------

def run_trivy(target: str) -> dict:
    cmd = ["trivy", "filesystem", "--scanners", "vuln,misconfig,license",
           "--list-all-pkgs", "--format", "json", "--quiet", target]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    if out.returncode != 0:
        sys.exit("trivy failed: " + out.stderr[:400])
    return json.loads(out.stdout)


def store_blob(raw: dict, out_dir: str) -> str:
    blob_dir = os.path.join(out_dir, "blobs")
    os.makedirs(blob_dir, exist_ok=True)
    data = canonical(raw)
    h = sha256(data)
    path = os.path.join(blob_dir, "sha256-" + h + ".json")
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(data)
    return h


# ---------------- Maps: Trivy -> observed facts (NO judgment) ----------------

def observe_1_1a(trivy: dict) -> dict:
    results = trivy.get("Results", []) or []
    pkgs = sum(len(r.get("Packages", []) or []) for r in results)
    ecosystems = sorted({r.get("Type", "?") for r in results if r.get("Packages")})
    return {
        "package_inventory": {"present": pkgs > 0, "count": pkgs,
                              "ecosystems": ecosystems},
        "sbom": {"present": pkgs > 0,
                 "note": "inventory enumerated by scan; no standalone SBOM artifact found in target"},
        "signed_attestation": {"present": False,
                               "note": "no signing attestation discovered by this pass"},
        "results_scanned": len(results),
    }


def observe_4_4a(trivy: dict) -> dict:
    sev = {}
    with_fix = 0
    total = 0
    for r in trivy.get("Results", []) or []:
        for v in r.get("Vulnerabilities", []) or []:
            total += 1
            s = (v.get("Severity") or "UNKNOWN").upper()
            sev[s] = sev.get(s, 0) + 1
            if v.get("FixedVersion"):
                with_fix += 1
    return {
        "vulnerability_findings": {"present": True, "total": total,
                                   "by_severity": dict(sorted(sev.items()))},
        "fix_availability": {"present": True, "fix_available": with_fix,
                             "no_fix_yet": total - with_fix},
        "note": "counts are observed facts from this scan; patch POLICY evidence arrives via export mode later",
    }


def observe_1_1b(trivy: dict) -> dict:
    sev = {}
    failures = 0
    successes = 0
    targets = 0
    for r in trivy.get("Results", []) or []:
        ms = r.get("Misconfigurations", []) or []
        summ = r.get("MisconfSummary") or {}
        if ms or summ:
            targets += 1
        successes += summ.get("Successes", 0)
        failures += summ.get("Failures", 0)
        for m in ms:
            s = (m.get("Severity") or "UNKNOWN").upper()
            sev[s] = sev.get(s, 0) + 1
    return {
        "misconfig_findings": {"present": failures > 0 or successes > 0,
                               "failed": failures, "by_severity": dict(sorted(sev.items()))},
        "checks_evaluated": {"present": (successes + failures) > 0,
                             "passed": successes, "failed": failures,
                             "config_targets": targets},
        "note": "IaC/config checks observed by trivy misconfig scanner; host CIS baseline arrives via Wazuh SCA later",
    }


def build_item(slot: str, kind: str, observation: dict, raw_hash: str,
               now: str, context: list, provenance: dict) -> dict:
    item = {
        "subcriterion": slot,
        "mode": "scanner",
        "source": {"tool": "trivy", "kind": kind, "raw_sha256": raw_hash},
        "provenance": provenance,   # WHICH box this evidence came from + how it was reached
        "observation": observation,
        "context": context,
        "completeness": completeness(observation, EXPECTED[slot]),
        "freshness": {"collected_utc": now, "evidence_age_seconds": 0,
                      "note": "live scan = age 0; documents carry their own dates"},
        "artifact_ref": "blob/sha256-" + raw_hash,
        "collected_utc": now,
    }
    item["item_sha256"] = sha256(canonical(item))
    return item


# ---------------- collect / verify ----------------

def collect(args):
    target = os.path.abspath(args.target)
    now = utcnow()
    trivy = run_trivy(target)
    os.makedirs(args.out_dir, exist_ok=True)
    raw_hash = store_blob(trivy, args.out_dir)

    context = ([{"type": "note", "text": args.note, "asserted_by": args.subject or "subject",
                 "asserted_utc": now, "verified": False, "epistemic": "subject_claim"}]
               if args.note else [])

    # Per-item provenance: which box, reached how. Defaults to the collecting
    # host for a local scan; --box names a remote target in a multi-box estate.
    provenance = {"box": args.box or platform.node(),
                  "access": "local-filesystem" if not args.box else "operator-specified",
                  "collector_host": platform.node(),
                  "target_path": target}

    items = [
        build_item("technology-v1:1.1a", "inventory+sbom", observe_1_1a(trivy), raw_hash, now, context, provenance),
        build_item("technology-v1:4.4a", "vulnerability", observe_4_4a(trivy), raw_hash, now, [], provenance),
        build_item("technology-v1:1.1b", "misconfig", observe_1_1b(trivy), raw_hash, now, [], provenance),
    ]

    subject = {"name": args.subject or os.path.basename(target),
               "scope": args.scope or ("filesystem:" + target),
               "collected_utc": now}
    collector = {"name": "beacon-collector", "version": VERSION,
                 "platform": platform.system().lower()}
    core = bl.build_package(subject, collector, items)
    try:
        package = bl.seal_and_sign(core, sign=args.sign, home=args.home)
    except RuntimeError as e:
        sys.exit(str(e))

    out_path = os.path.join(args.out_dir, "package.json")
    with open(out_path, "w") as f:
        f.write(json.dumps(package, indent=2))

    print("sealed evidence package -> " + out_path)
    for it in items:
        c = it["completeness"]
        print("  %-22s completeness %s (%d/%d)" % (
            it["subcriterion"], c["fraction"], len(c["obtained"]), len(c["expected"])))
    print("  package_hash: " + package["seal"]["package_hash"])
    print("  NO score anywhere in this package; leveling belongs to the scorer/CRC.")


def verify(args):
    with open(args.package) as f:
        pkg = json.load(f)
    blob_dir = args.blobs or os.path.join(os.path.dirname(os.path.abspath(args.package)), "blobs")
    ok = bl.verify_package(pkg, blob_dir=blob_dir, registry=args.registry)
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--target", required=True)
    c.add_argument("--subject")
    c.add_argument("--scope")
    c.add_argument("--note")
    c.add_argument("--out-dir", default="out")
    c.add_argument("--box", help="label for the box this evidence is from (per-item provenance in a multi-box estate)")
    c.add_argument("--sign", action="store_true", help="sign with the enrolled identity key")
    c.add_argument("--home", default=os.path.expanduser("~/.beacon"), help="enrollment home")
    v = sub.add_parser("verify")
    v.add_argument("package")
    v.add_argument("--blobs")
    v.add_argument("--registry", help="registry-stub dir to check the signing key against (anti-forge)")
    a = ap.parse_args()
    (collect if a.cmd == "collect" else verify)(a)


if __name__ == "__main__":
    main()
