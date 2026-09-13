#!/usr/bin/env python3
"""
docs.py, Beacon Collector 0.4: the DOCUMENT collector (breadth mode).

Proves BREADTH (the 0.4 milestone). Scanner mode (collector.py) gives live,
verifiable depth on a few Technology slots. Document mode gives WIDTH: one audit
artifact (SOC 2 Type II, pen-test report, policy set) attests to dozens of
subcriteria across every rubric at once. The pitch: "show me your SOC 2" lights
up People, Process, and Technology slots from a single sealed ingest.

Honest epistemics (invariant discipline):
  - A scanner OBSERVES facts. A document RELAYS a third party's ATTESTATION.
    These are different evidence classes and must never be conflated.
  - Every document-mode item is epistemic="third_party_attestation",
    verified_by_collector=false. The collector verifies the DOCUMENT's integrity
    (hash), NOT the truth of the auditor's claims. Whether to trust the auditor
    is the scorer's / CRC assessor's judgment, downstream.
  - Section detection here is DETERMINISTIC (published crosswalk + text match),
    so the "which controls does this report cover" claim is itself an observed
    fact about the document, reproducible without an LLM. LLM-assisted extraction
    is an optional future enrichment, and would be labeled as parse, never as
    attestation.

  docs.py collect --doc REPORT.txt --doc-type soc2|pentest --subject NAME \
       [--sign --home ~/.beacon] [--out-dir out-docs]
  docs.py verify PACKAGE.json [--registry DIR] [--blobs DIR]

Reuses beaconlib for identical seal/sign/verify as scanner mode.
"""
import argparse
import os
import re
import sys

import beaconlib as bl

# ---- Published crosswalk: audit-framework control -> beacon subcriterion slot.
# Deterministic and auditable. Each control id maps to the slot(s) a positive
# finding in that control attests to. This is the "one report -> many slots" map.
SOC2_CROSSWALK = {
    "CC6.1": ["technology-v1:2.2a", "people-v1:mfa"],          # logical access / auth
    "CC6.2": ["people-v1:jml"],                                 # registration/deprovision
    "CC6.3": ["people-v1:least-privilege"],                     # least privilege
    "CC6.6": ["technology-v1:4.4c"],                            # boundary protection
    "CC6.7": ["data-v1:in-transit"],                            # transmission encryption
    "CC6.8": ["technology-v1:1.1b"],                            # config / malware controls
    "CC7.1": ["technology-v1:1.1a"],                            # inventory / change detection
    "CC7.2": ["technology-v1:6.6a"],                            # monitoring / SIEM
    "CC7.3": ["process-v1:incident-response"],                  # incident evaluation
    "CC7.4": ["process-v1:incident-response"],                  # incident response
    "CC8.1": ["process-v1:change-management"],                  # change management
    "A1.2":  ["data-v1:backup-recovery"],                       # availability / backup
    "C1.1":  ["data-v1:retention"],                             # confidentiality retention
}
PENTEST_CROSSWALK = {
    "external-network": ["technology-v1:4.4c"],
    "web-application":  ["technology-v1:6.6c"],
    "vulnerability-assessment": ["technology-v1:4.4a"],
    "remediation-retest": ["process-v1:control-effectiveness"],
}
CROSSWALKS = {"soc2": SOC2_CROSSWALK, "pentest": PENTEST_CROSSWALK}


def detect_controls(text: str, crosswalk: dict) -> dict:
    """Deterministic presence detection: which crosswalk keys appear in the doc.
    Word-boundary match so 'CC6.1' doesn't spuriously match 'CC6.11'."""
    found = {}
    upper = text
    for control in crosswalk:
        pat = r"(?<![\w.])" + re.escape(control) + r"(?![\w.])"
        hits = len(re.findall(pat, upper, flags=re.IGNORECASE))
        if hits:
            found[control] = hits
    return found


def collect(args):
    doc_type = args.doc_type
    crosswalk = CROSSWALKS.get(doc_type)
    if not crosswalk:
        sys.exit("unknown --doc-type %r (have: %s)" % (doc_type, ", ".join(CROSSWALKS)))
    if not os.path.exists(args.doc):
        sys.exit("document not found: %s" % args.doc)

    with open(args.doc, "rb") as f:
        raw = f.read()
    doc_hash = bl.sha256(raw)
    text = raw.decode("utf-8", errors="replace")
    now = bl.utcnow()

    os.makedirs(args.out_dir, exist_ok=True)
    blob_dir = os.path.join(args.out_dir, "blobs")
    os.makedirs(blob_dir, exist_ok=True)
    with open(os.path.join(blob_dir, "sha256-" + doc_hash + ".json"), "wb") as f:
        f.write(raw)  # the artifact itself is the blob (verbatim, hashed)

    found = detect_controls(text, crosswalk)
    if not found:
        print("warning: no known %s controls detected in document; nothing to attest" % doc_type)

    # Build one document-mode item per beacon slot the detected controls attest to.
    slot_to_controls = {}
    for control in found:
        for slot in crosswalk[control]:
            slot_to_controls.setdefault(slot, []).append(control)

    items = []
    for slot, controls in sorted(slot_to_controls.items()):
        observation = {
            "attested": {"present": True,
                         "source_controls": sorted(controls),
                         "note": "the document ASSERTS coverage of these controls; not independently verified by the collector"},
        }
        item = {
            "subcriterion": slot,
            "mode": "document",
            "source": {"tool": doc_type + "-report", "kind": "audit_artifact",
                       "raw_sha256": doc_hash,
                       "document_name": os.path.basename(args.doc)},
            "observation": observation,
            "epistemic": "third_party_attestation",
            "verified_by_collector": False,
            "context": [],
            "completeness": {"expected": ["attested"], "obtained": ["attested"],
                             "fraction": 1.0,
                             "note": "attestation present for this slot; DEPTH still wants a live scan"},
            "freshness": {"collected_utc": now,
                          "note": "document mode: the report's OWN date governs age; ingest date is not evidence age"},
            "artifact_ref": "blob/sha256-" + doc_hash,
            "collected_utc": now,
        }
        items.append(item)

    subject = {"name": args.subject or os.path.basename(args.doc),
               "scope": "document:" + doc_type, "collected_utc": now}
    collector = {"name": "beacon-document-collector", "version": "0.4.0",
                 "platform": "any"}
    core = bl.build_package(subject, collector, items)
    package = bl.seal_and_sign(core, sign=args.sign, home=args.home)

    out_path = os.path.join(args.out_dir, "package.json")
    import json
    with open(out_path, "w") as f:
        f.write(json.dumps(package, indent=2))
    bl.anchor_after_write(out_path, sealed_utc=subject.get("collected_utc"), home=args.home, enabled=not args.no_anchor)

    rubrics = sorted({it["subcriterion"].split(":")[0] for it in items})
    print("ingested %s (%s), sha256 %s..." % (os.path.basename(args.doc), doc_type, doc_hash[:12]))
    print("  detected %d controls -> %d beacon slots across %d rubrics: %s" % (
        len(found), len(items), len(rubrics), ", ".join(rubrics)))
    for it in items:
        print("    %-32s <- %s" % (it["subcriterion"], ",".join(it["observation"]["attested"]["source_controls"])))
    print("  ALL items epistemic=third_party_attestation (auditor's claim, not our observation)")
    print("  sealed -> %s  |  package_hash %s" % (out_path, package["seal"]["package_hash"][:16]))
    print("  NO score; leveling belongs to the scorer/CRC.")


def verify(args):
    import json
    pkg = json.load(open(args.package))
    blob_dir = args.blobs or os.path.join(os.path.dirname(os.path.abspath(args.package)), "blobs")
    ok = bl.verify_package(pkg, blob_dir=blob_dir, registry=args.registry)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--doc", required=True)
    c.add_argument("--doc-type", required=True)
    c.add_argument("--subject")
    c.add_argument("--sign", action="store_true")
    c.add_argument("--no-anchor", action="store_true", help="seal only; do not timestamp/anchor the package (state recorded as unanchored)")
    c.add_argument("--home", default=os.path.expanduser("~/.beacon"))
    c.add_argument("--out-dir", default="out-docs")
    v = sub.add_parser("verify")
    v.add_argument("package")
    v.add_argument("--registry")
    v.add_argument("--blobs")
    a = ap.parse_args()
    (collect if a.cmd == "collect" else verify)(a)
