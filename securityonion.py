#!/usr/bin/env python3
"""
securityonion.py, Beacon Collector: Security Onion connector (export mode).

Proves the DOUG CHANNEL. Security Onion is Wazuh-based NSM/SIEM; a single SO
install already holds posture-relevant evidence (Wazuh SCA config checks, agent
coverage, detection/log coverage). This connector ingests a Security Onion
posture export and maps it to beacon evidence items, epistemic="observed_export"
(real monitoring data). Doubles as the REFERENCE for what a Security Onion
"posture export" (the ask to Doug Burks) would emit natively — every SO install
becomes a Collector feeder.

Maps to:
  technology-v1:1.1b  config baseline    <- Wazuh SCA (CIS/policy pass/fail)
  technology-v1:4.4b  endpoint coverage  <- Wazuh agent enrollment/active
  technology-v1:6.6a  SIEM & monitoring  <- detection rules + log-source coverage

Input: a JSON export (from SO's API / a saved query), shape below. Since the
mapping is deterministic, the connector emits OBSERVED FACTS + evidence-quality
metadata; it never scores.

Expected export shape (also the Doug posture-export spec, v0):
  {
    "sca": {"policies": [{"name":"cis_...","pass":N,"fail":M,"score":P}, ...]},
    "agents": {"total":N, "active":M, "disconnected":K},
    "detections": {"rules_enabled":N, "log_sources":M, "coverage_note":"..."}
  }

  securityonion.py collect --export SO.json --subject NAME [--sign --home ~/.beacon] [--out-dir out-so]
  securityonion.py verify PACKAGE.json [--registry DIR] [--blobs DIR]
"""
import argparse
import json
import os
import sys

import beaconlib as bl


def observe(export: dict) -> dict:
    out = {}

    sca = export.get("sca", {}) or {}
    policies = sca.get("policies", []) or []
    total_pass = sum(int(p.get("pass", 0)) for p in policies)
    total_fail = sum(int(p.get("fail", 0)) for p in policies)
    out["technology-v1:1.1b"] = {"misconfig_findings": {
        "present": (total_pass + total_fail) > 0,
        "policies": [{"name": p.get("name"), "pass": p.get("pass"), "fail": p.get("fail"),
                      "score": p.get("score")} for p in policies],
        "checks_passed": total_pass, "checks_failed": total_fail,
        "note": "Wazuh SCA config-policy results from Security Onion; observed, not self-attested"}}

    ag = export.get("agents", {}) or {}
    total = int(ag.get("total", 0)); active = int(ag.get("active", 0))
    out["technology-v1:4.4b"] = {"endpoint_coverage": {
        "present": total > 0, "agents_total": total, "agents_active": active,
        "coverage_fraction": round(active / total, 3) if total else None,
        "disconnected": int(ag.get("disconnected", 0)),
        "note": "Wazuh agent enrollment/active from Security Onion; endpoint monitoring coverage is a FACT, not a grade"}}

    det = export.get("detections", {}) or {}
    out["technology-v1:6.6a"] = {"monitoring": {
        "present": bool(det),
        "rules_enabled": int(det.get("rules_enabled", 0)),
        "log_sources": int(det.get("log_sources", 0)),
        "note": det.get("coverage_note", "detection + log-source coverage observed from Security Onion")}}

    return out


EXPECTED = {
    "technology-v1:1.1b": ["misconfig_findings"],
    "technology-v1:4.4b": ["endpoint_coverage"],
    "technology-v1:6.6a": ["monitoring"],
}


def collect(args):
    if not os.path.exists(args.export):
        sys.exit("Security Onion export not found: %s" % args.export)
    with open(args.export, "rb") as f:
        raw = f.read()
    raw_hash = bl.sha256(raw)
    try:
        export = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.exit("export is not valid JSON: %s" % e)

    now = bl.utcnow()
    os.makedirs(args.out_dir, exist_ok=True)
    blob_dir = os.path.join(args.out_dir, "blobs")
    os.makedirs(blob_dir, exist_ok=True)
    with open(os.path.join(blob_dir, "sha256-" + raw_hash + ".json"), "wb") as f:
        f.write(raw)

    provenance = {"box": args.box or "security-onion", "access": "security-onion-export",
                  "source_system": "security-onion(wazuh)"}
    observations = observe(export)

    items = []
    for slot, obs in observations.items():
        obs_key = list(obs.keys())[0]
        item = {
            "subcriterion": slot, "mode": "export",
            "source": {"tool": "security-onion", "kind": "nsm_siem_export",
                       "raw_sha256": raw_hash, "export_name": os.path.basename(args.export)},
            "provenance": provenance,
            "observation": obs,
            "epistemic": "observed_export", "verified_by_collector": True,
            "context": [],
            "completeness": bl.completeness({obs_key: obs[obs_key]}, [obs_key]),
            "freshness": {"collected_utc": now, "evidence_age_seconds": 0,
                          "note": "SO export reflects monitoring state at export time"},
            "artifact_ref": "blob/sha256-" + raw_hash, "collected_utc": now,
        }
        items.append(item)

    subject = {"name": args.subject or "unknown", "scope": "security-onion", "collected_utc": now}
    collector = {"name": "beacon-securityonion-connector", "version": "0.6.0", "platform": "any"}
    core = bl.build_package(subject, collector, items)
    try:
        package = bl.seal_and_sign(core, sign=args.sign, home=args.home)
    except RuntimeError as e:
        sys.exit(str(e))

    out_path = os.path.join(args.out_dir, "package.json")
    with open(out_path, "w") as f:
        f.write(json.dumps(package, indent=2))

    sca = observations["technology-v1:1.1b"]["misconfig_findings"]
    ep = observations["technology-v1:4.4b"]["endpoint_coverage"]
    print("ingested Security Onion export (%s), sha256 %s..." % (os.path.basename(args.export), raw_hash[:12]))
    print("  technology-v1:1.1b config   SCA %d passed / %d failed across %d policies" % (
        sca["checks_passed"], sca["checks_failed"], len(sca["policies"])))
    print("  technology-v1:4.4b endpoint agents %d/%d active (%s)" % (
        ep["agents_active"], ep["agents_total"], ep["coverage_fraction"]))
    print("  technology-v1:6.6a monitoring rules=%d log_sources=%d" % (
        observations["technology-v1:6.6a"]["monitoring"]["rules_enabled"],
        observations["technology-v1:6.6a"]["monitoring"]["log_sources"]))
    print("  epistemic=observed_export (one Security Onion install feeds 3 slots); NO score")
    print("  package_hash: %s" % package["seal"]["package_hash"][:16])


def verify(args):
    pkg = json.load(open(args.package))
    blob_dir = args.blobs or os.path.join(os.path.dirname(os.path.abspath(args.package)), "blobs")
    ok = bl.verify_package(pkg, blob_dir=blob_dir, registry=args.registry)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--export", required=True)
    c.add_argument("--subject")
    c.add_argument("--box")
    c.add_argument("--sign", action="store_true")
    c.add_argument("--home", default=os.path.expanduser("~/.beacon"))
    c.add_argument("--out-dir", default="out-so")
    v = sub.add_parser("verify")
    v.add_argument("package")
    v.add_argument("--registry")
    v.add_argument("--blobs")
    a = ap.parse_args()
    (collect if a.cmd == "collect" else verify)(a)
