#!/usr/bin/env python3
"""
report.py, Beacon Collector: framework crosswalk report (the "sample").

Reads a SEALED evidence package and produces a coverage report against a
framework's controls, each line labeled by EVIDENCE GRADE. This is the free,
self-attested "sample" of CRC decision #10, and it is also the CRA Annex I
Part II treatment-evidence artifact validated 2026-07-29.

Two hard rules from the founder decisions, enforced here:
  - NEVER certify. Output says "evidence-backed POSITION against <framework>",
    never "compliant". A map, not a blessing.
  - LEAD with verified-vs-attested. Every control shows the strongest evidence
    grade backing it: observed > attested > subject_claim > none. That honest
    labeling is the whole differentiator over a GRC checkbox tool, and it is why
    getting the evidence independently verified (a CRC engagement) is obviously
    worth it: the gaps and the merely-claimed controls sell themselves.

No score. Coverage + evidence grade are facts about the evidence, not a posture
judgment. Verifies the package seal first and refuses a tampered package.

  report.py PACKAGE.json [--framework cra-annex-i] [--md OUT.md]
"""
import argparse
import json
import os
import sys

import beaconlib as bl

# Evidence grade ranking (strongest first). Derived from an item's mode +
# epistemic tag. "observed" = a scan/export saw it; "attested" = a document
# claims it; "subject_claim" = the subject asserted it in a note.
GRADE_ORDER = ["observed", "attested", "subject_claim", "none"]

def item_grade(item: dict) -> str:
    ep = item.get("epistemic")
    if ep == "observed_export":
        return "observed"
    if ep == "third_party_attestation":
        return "attested"
    if ep == "subject_claim":
        return "subject_claim"
    # scanner mode with a present observation = observed fact
    if item.get("mode") == "scanner":
        return "observed"
    return "subject_claim"

def strongest(grades):
    for g in GRADE_ORDER:
        if g in grades:
            return g
    return "none"

# ---- published crosswalk: CRA Annex I requirement <- beacon subcriterion slots.
# Indicative mapping, versioned. A positive finding in the mapped slot evidences
# the requirement. (Authored; ties to the collector's emitted slots + docs.py.)
CRA_ANNEX_I = {
    "version": "vcri.crosswalk.cra-annex-i/0.1",
    "name": "EU CRA Annex I (essential requirements)",
    "controls": [
        {"id": "I.2b", "t": "Secure by default", "slots": ["technology-v1:1.1b"]},
        {"id": "I.2c", "t": "Secure update mechanism", "slots": ["process-v1:change-management"]},
        {"id": "I.2d", "t": "Protection from unauthorized access", "slots": ["technology-v1:2.2a", "people-v1:mfa", "people-v1:jml", "people-v1:least-privilege"]},
        {"id": "I.2e", "t": "Confidentiality protection", "slots": ["data-v1:in-transit"]},
        {"id": "I.2f", "t": "Integrity protection", "slots": ["technology-v1:1.1a"]},
        {"id": "I.2h", "t": "Availability protection", "slots": ["data-v1:backup-recovery"]},
        {"id": "I.2j", "t": "Attack-surface limitation", "slots": ["technology-v1:1.1b", "technology-v1:4.4c"]},
        {"id": "I.2k", "t": "Impact reduction / resilience", "slots": ["people-v1:least-privilege"]},
        {"id": "I.2l", "t": "Recording & monitoring", "slots": ["technology-v1:6.6a"]},
        {"id": "I.2m", "t": "Secure data removal", "slots": ["data-v1:retention"]},
        {"id": "II.1", "t": "Vulnerability identification & SBOM", "slots": ["technology-v1:1.1a", "technology-v1:4.4a"]},
        {"id": "II.2", "t": "Vulnerability remediation", "slots": ["technology-v1:4.4a", "process-v1:incident-response"]},
        {"id": "II.3", "t": "Regular tests", "slots": ["technology-v1:6.6c", "process-v1:control-effectiveness"]},
    ],
}
FRAMEWORKS = {"cra-annex-i": CRA_ANNEX_I}


def slot_present(item: dict) -> bool:
    obs = item.get("observation", {})
    # present if any sub-observation says present, or it's an attestation item
    if item.get("epistemic") == "third_party_attestation":
        return True
    for v in obs.values():
        if isinstance(v, dict) and v.get("present"):
            return True
    return False


def build(pkg: dict, fw: dict):
    # index items by subcriterion -> list of (grade, present)
    by_slot = {}
    for it in pkg.get("items", []):
        by_slot.setdefault(it["subcriterion"], []).append(it)
    rows = []
    for c in fw["controls"]:
        mapped = []
        for slot in c["slots"]:
            for it in by_slot.get(slot, []):
                mapped.append(it)
        present_items = [it for it in mapped if slot_present(it)]
        if not mapped:
            coverage, grade, srcs = "absent", "none", []
        elif present_items:
            grade = strongest([item_grade(it) for it in present_items])
            # partial if only some mapped slots have present evidence
            slots_hit = {it["subcriterion"] for it in present_items}
            coverage = "covered" if slots_hit >= set(c["slots"]) else "partial"
            srcs = sorted({it["subcriterion"] for it in present_items})
        else:
            coverage, grade, srcs = "absent", "none", []
        rows.append({"id": c["id"], "t": c["t"], "coverage": coverage,
                     "grade": grade, "sources": srcs})
    return rows


def render_md(pkg, fw, rows):
    subj = pkg.get("subject", {}).get("name", "subject")
    counts = {"covered": 0, "partial": 0, "absent": 0}
    gcounts = {g: 0 for g in GRADE_ORDER}
    for r in rows:
        counts[r["coverage"]] += 1
        gcounts[r["grade"]] += 1
    out = []
    out.append("# Framework coverage report: %s" % fw["name"])
    out.append("")
    out.append("**Subject:** %s  \n**Framework:** %s  \n**Crosswalk:** `%s`" % (
        subj, fw["name"], fw["version"]))
    out.append("")
    out.append("> **Indicative, evidence-backed, NOT a certification.** This shows where the "
               "subject's collected evidence maps to the framework's controls, and the grade of "
               "evidence behind each. It is not a conformance determination. Independent "
               "verification (a Cairn Risk Co. engagement) upgrades `attested` and `subject_claim` "
               "lines toward `observed`.")
    out.append("")
    out.append("**Coverage:** %d covered · %d partial · %d absent  \n**Evidence grade:** %d observed · %d attested · %d subject-claim · %d none" % (
        counts["covered"], counts["partial"], counts["absent"],
        gcounts["observed"], gcounts["attested"], gcounts["subject_claim"], gcounts["none"]))
    out.append("")
    out.append("| Control | Coverage | Evidence grade | Source evidence |")
    out.append("|---|---|---|---|")
    for r in rows:
        out.append("| **%s** %s | %s | %s | %s |" % (
            r["id"], r["t"], r["coverage"], r["grade"],
            ", ".join(r["sources"]) if r["sources"] else "—"))
    out.append("")
    gaps = [r for r in rows if r["coverage"] != "covered" or r["grade"] in ("subject_claim",)]
    if gaps:
        out.append("## Where verification would help most")
        for r in gaps:
            why = "no evidence collected" if r["coverage"] == "absent" else (
                "only self-claimed" if r["grade"] == "subject_claim" else "partial coverage")
            out.append("- **%s %s** — %s." % (r["id"], r["t"], why))
    out.append("")
    out.append("*Generated by the Beacon Collector. No score is assigned; leveling and verified "
               "rating are Cairn Risk Co. Schema %s.*" % pkg.get("schema", "?"))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("package")
    ap.add_argument("--framework", default="cra-annex-i", choices=list(FRAMEWORKS))
    ap.add_argument("--md")
    a = ap.parse_args()

    pkg = json.load(open(a.package))
    # refuse a tampered package (report only on intact evidence)
    blob_dir = os.path.join(os.path.dirname(os.path.abspath(a.package)), "blobs")
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ok = bl.verify_package(pkg, blob_dir=blob_dir if os.path.isdir(blob_dir) else None)
    if not ok:
        sys.exit("refusing to report: package failed seal verification.\n" + buf.getvalue())

    fw = FRAMEWORKS[a.framework]
    rows = build(pkg, fw)
    md = render_md(pkg, fw, rows)
    if a.md:
        open(a.md, "w").write(md + "\n")
        print("report -> " + a.md)
    # console summary
    cov = sum(1 for r in rows if r["coverage"] == "covered")
    print("%s vs %s: %d/%d controls covered" % (
        pkg.get("subject", {}).get("name", "subject"), fw["name"], cov, len(rows)))
    for r in rows:
        print("  %-7s %-34s %-8s %s" % (r["id"], r["t"][:34], r["coverage"], r["grade"]))
    print("  (indicative, evidence-backed, NOT a certification; NO score)")


if __name__ == "__main__":
    main()
