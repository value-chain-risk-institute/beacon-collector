#!/usr/bin/env python3
"""
beacon.py — BeaconScore Collector, spike 0.

One tool (Trivy) -> one map (subcriterion 1.1a) -> OBSERVED FACTS + freshness +
completeness (+ optional sealed subject notes) -> ONE tamper-evident package.

The collector does NOT rate. Scoring is posture judgment and belongs to the
scorer / Cairn Risk Co, computed from this sealed evidence. The whole package
is bound to a SHA-256 hash: the subject cannot edit the evidence, the metadata,
or its own notes without invalidating the seal (Joshua, 2026-07-28: collector
collects+collates+seals; the vendor can't fake what it can't alter).

  beacon.py collect --target <path> [--note "..."]  # collect, seal -> package.json
  beacon.py collect --mock                          # same, using sample Trivy output
  beacon.py verify  <package.json>                  # recompute hash; PASS only if untampered

Self-hosted, org-owns-output. No network. Signature + PQC-send + OpenTimestamps
anchor are the next hardening block (stubbed here; hash-binding is spike 0).
"""
import json, hashlib, subprocess, sys, argparse, os
from datetime import datetime, timezone

SUBCRITERION = {
    "key": "tech-1.1a",
    "title": "Asset inventory and software provenance/SBOM",
    "rubric": "technology-v1",
}

# ---- ONE MAP: Trivy findings -> OBSERVATION FACTS for tech 1.1a -----------
# The collector does NOT compute a 0-5 level. Leveling is posture judgment and
# belongs to the scorer/CRC, from this sealed evidence. The collector reports
# only OBSERVED FACTS + evidence-quality metadata (freshness, completeness).
#
# Expected evidence types for slot tech-1.1a (drives COMPLETENESS, not a score):
EXPECTED_1_1A = ["package_inventory", "sbom", "signed_attestation"]

def observe_trivy_1_1a(trivy: dict) -> dict:
    results = trivy.get("Results", []) or []
    pkg_count = sum(len(r.get("Packages", []) or []) for r in results)
    has_sbom = any(r.get("Type") in ("bom", "cyclonedx", "spdx") for r in results) \
        or (trivy.get("SchemaVersion") is not None and any(r.get("Packages") for r in results))
    signed = bool(trivy.get("_signed_attestation"))
    return {
        "package_inventory": {"present": pkg_count > 0, "count": pkg_count},
        "sbom": {"present": has_sbom},
        "signed_attestation": {"present": signed},
        "results_scanned": len(results),
    }

def completeness(observation: dict, expected: list[str]) -> dict:
    got = [k for k in expected if observation.get(k, {}).get("present")]
    return {"expected": expected, "obtained": got,
            "fraction": round(len(got) / len(expected), 3) if expected else None,
            "note": "coverage of THIS package's evidence, not a posture grade"}

def run_trivy(target: str) -> dict:
    # SBOM + package inventory in one pass; JSON to stdout.
    out = subprocess.run(
        ["trivy", "filesystem" if os.path.exists(target) else "image",
         "--format", "json", "--list-all-pkgs", "--quiet", target],
        capture_output=True, text=True, timeout=600,
    )
    if out.returncode != 0:
        sys.exit(f"trivy failed: {out.stderr[:300]}")
    return json.loads(out.stdout)

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def seal(bundle_core: dict) -> dict:
    h = hashlib.sha256(canonical(bundle_core)).hexdigest()
    return {**bundle_core, "seal": {"alg": "sha256", "hash": h,
            "note": "score is bound to this hash; edit any field above and verify fails",
            "signature": "STUB-spike0", "anchor": "STUB-spike0-opentimestamps"}}

def collect(args):
    if args.mock:
        trivy = json.loads(open(os.path.join(os.path.dirname(__file__), "sample-trivy.json")).read())
        target = "MOCK:sample-node-app"
    else:
        trivy = run_trivy(args.target); target = args.target
    now = args.now or datetime.now(timezone.utc).isoformat()
    observation = observe_trivy_1_1a(trivy)
    core = {
        "schema": "vcri.beacon.evidence-package/v0",
        "subcriterion": SUBCRITERION,   # the SLOT this evidence maps to — NOT a score
        "target": target,
        "collector_version": "0.1.0-spike0",
        "collected_utc": now,
        "tool": {"name": "trivy", "mode": "scanner", "raw_sha256": hashlib.sha256(canonical(trivy)).hexdigest()},
        "observation": observation,     # OBSERVED FACTS only; no judgment
        "context": ([{                  # OPTIONAL subject CLAIM — sealed, but unverified; scorer may weigh, self-score ignores
            "type": "note", "text": args.note, "asserted_utc": now,
            "verified": False, "epistemic": "subject_claim",
        }] if args.note else []),
        "completeness": completeness(observation, EXPECTED_1_1A),
        "freshness": {"collected_utc": now, "evidence_age_seconds": 0,
                      "note": "live scan = age 0; ingested documents carry the document's own date"},
    }
    bundle = seal(core)
    open(args.out, "w").write(json.dumps(bundle, indent=2))
    comp = bundle["completeness"]
    print(f"✓ collected {SUBCRITERION['key']}  ·  completeness {comp['fraction']} ({len(comp['obtained'])}/{len(comp['expected'])})  ·  NO score (that's the scorer's job)  ·  sealed → {args.out}")
    print(f"  seal hash: {bundle['seal']['hash']}")

def verify(args):
    b = json.loads(open(args.bundle).read())
    claimed = b.get("seal", {}).get("hash")
    core = {k: v for k, v in b.items() if k != "seal"}
    recomputed = hashlib.sha256(canonical(core)).hexdigest()
    if recomputed == claimed:
        print(f"✓ VALID — seal intact. Evidence for {b['subcriterion']['key']} (completeness {b['completeness']['fraction']}) is bound and unaltered; safe to score.")
    else:
        print("✗ TAMPERED — seal does NOT match evidence. This package was edited after collection; reject it.")
        print(f"  claimed:    {claimed}\n  recomputed: {recomputed}")
        sys.exit(1)

ap = argparse.ArgumentParser()
sub = ap.add_subparsers(dest="cmd", required=True)
c = sub.add_parser("collect"); c.add_argument("--target", default="."); c.add_argument("--mock", action="store_true")
c.add_argument("--out", default="bundle.json"); c.add_argument("--now"); c.add_argument("--note")
v = sub.add_parser("verify"); v.add_argument("bundle")
a = ap.parse_args()
(collect if a.cmd == "collect" else verify)(a)
