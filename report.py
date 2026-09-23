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

# Versioned crosswalks shipped as files (public, arguable, diffable). Key = file stem.
_CW_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crosswalks")
if os.path.isdir(_CW_DIR):
    for _fn in sorted(os.listdir(_CW_DIR)):
        if _fn.endswith(".json") and not _fn.endswith(".source.json"):
            try:
                with open(os.path.join(_CW_DIR, _fn)) as _f:
                    _fw = json.load(_f)
                if isinstance(_fw, dict) and "controls" in _fw:
                    FRAMEWORKS[_fn[:-5]] = _fw
            except Exception:
                pass

CLASS_LABEL = {"observed": "Observed", "attested": "Attested", "subject_claim": "Stated", "none": "None"}


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
        if not c.get("slots"):
            coverage, grade, srcs = "manual", "none", []
        elif not mapped:
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
                     "grade": grade, "sources": srcs,
                     "family": c.get("family"), "kind": c.get("kind"), "slots": list(c.get("slots", []))})
    return rows


def render_md(pkg, fw, rows):
    subj = pkg.get("subject", {}).get("name", "subject")
    counts = {"covered": 0, "partial": 0, "absent": 0, "manual": 0}
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
    out.append("**Coverage:** %d covered · %d partial · %d absent · %d no automated source  \n**Evidence grade:** %d observed · %d attested · %d stated · %d none" % (
        counts["covered"], counts["partial"], counts["absent"], counts["manual"],
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


def render_json(pkg, fw, rows):
    seal = pkg.get("seal", {}) or {}
    return {
        "schema": "vcri.beacon.framework-coverage/v0",
        "framework": {"key": fw.get("version"), "name": fw.get("name"), "status": fw.get("status"), "source": fw.get("source")},
        "subject": pkg.get("subject", {}),
        "package": {"schema": pkg.get("schema"), "hash": seal.get("hash"), "sealed_utc": seal.get("sealed_utc") or pkg.get("collected_utc"), "anchor": seal.get("anchor")},
        "not_this": fw.get("not_this", []),
        "classes": fw.get("classes", {}),
        "rows": rows,
    }


def render_html(pkg, fw, rows):
    import html as _h
    subj = pkg.get("subject", {}) or {}
    seal = pkg.get("seal", {}) or {}
    fams = []
    for r in rows:
        f = r.get("family") or "Requirements"
        if f not in fams:
            fams.append(f)
    def cls(r):
        return {"observed": "obs", "attested": "att", "subject_claim": "sta", "none": "non"}[r["grade"]]
    tot = {"covered": 0, "partial": 0, "absent": 0, "manual": 0}
    for r in rows:
        tot[r["coverage"]] += 1
    css = """
    body{font-family:-apple-system,Helvetica,Arial,sans-serif;font-size:13px;color:#1a1a1a;margin:0;background:#f3f4f6}
    main{max-width:1000px;margin:0 auto;padding:28px 20px 60px;background:#fff}
    h1{font-size:22px;margin:0 0 4px;color:#0b2545}h2{font-size:15px;margin:22px 0 6px;color:#0b2545;border-bottom:1px solid #e3e3e3;padding-bottom:3px}
    .sub{color:#555;font-size:12px;margin:0 0 14px}
    .warn{background:#fff7e6;border-left:4px solid #b8860b;padding:8px 12px;margin:10px 0 16px;font-size:12.5px}
    .kpis{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0}.kpi{border:1px solid #e3e3e3;border-radius:8px;padding:8px 12px;min-width:120px}.kpi b{display:block;font-size:18px;color:#0b2545}.kpi span{font-size:11px;color:#666;text-transform:uppercase;letter-spacing:.4px}
    table{width:100%;border-collapse:collapse;font-size:12px;margin:4px 0 10px}th,td{border:1px solid #e3e3e3;padding:5px 7px;text-align:left;vertical-align:top}th{background:#f6f6f2}
    td.id{font-family:ui-monospace,Menlo,monospace;white-space:nowrap;font-weight:600}
    .pill{display:inline-block;border-radius:4px;padding:1px 6px;font-size:11px;font-weight:600}
    .obs{background:#e6f2ec;color:#1f6f4a}.att{background:#fdf1dc;color:#8a5a00}.sta{background:#f5e6e6;color:#8a1c1c}.non{background:#eee;color:#666}
    .cov-covered{color:#1f6f4a;font-weight:600}.cov-partial{color:#8a5a00;font-weight:600}.cov-absent{color:#8a1c1c;font-weight:600}.cov-manual{color:#666}
    .foot{font-size:11px;color:#666;margin-top:26px;border-top:1px solid #e3e3e3;padding-top:8px}
    @media print{body{background:#fff}main{padding:0}}
    """
    h = ["<!doctype html><html><head><meta charset=\"utf-8\"><title>%s: evidence coverage</title><style>%s</style></head><body><main>" % (_h.escape(fw.get("name", "framework")), css)]
    h.append("<h1>Evidence coverage against %s</h1>" % _h.escape(fw.get("name", "")))
    h.append("<p class=\"sub\"><b>Subject:</b> %s &nbsp;·&nbsp; <b>Package:</b> %s &nbsp;·&nbsp; <b>Sealed:</b> %s &nbsp;·&nbsp; <b>Crosswalk:</b> %s</p>" % (
        _h.escape(str(subj.get("name", "subject"))), _h.escape(str(seal.get("hash", "?"))[:24]) + "…", _h.escape(str(seal.get("sealed_utc") or pkg.get("collected_utc") or "?")), _h.escape(str(fw.get("version", "")))))
    h.append("<div class=\"warn\"><b>What this is, and is not.</b> This shows where the subject's sealed evidence speaks to each requirement, and the class of evidence behind it: "
             "<span class=\"pill obs\">Observed</span> collected from a system of record or a scanner; <span class=\"pill att\">Attested</span> a third party's report, ingested and sealed; "
             "<span class=\"pill sta\">Stated</span> the subject's own claim, sealed but unverified. " + " ".join(_h.escape(x) for x in fw.get("not_this", [])) +
             " Independent verification upgrades Attested and Stated lines toward Observed.</div>")
    h.append("<div class=\"kpis\"><div class=\"kpi\"><b>%d</b><span>requirements</span></div><div class=\"kpi\"><b>%d</b><span>covered</span></div><div class=\"kpi\"><b>%d</b><span>partial</span></div><div class=\"kpi\"><b>%d</b><span>no evidence yet</span></div><div class=\"kpi\"><b>%d</b><span>no automated source</span></div></div>" % (
        len(rows), tot["covered"], tot["partial"], tot["absent"], tot["manual"]))
    for fam in fams:
        frows = [r for r in rows if (r.get("family") or "Requirements") == fam]
        c = sum(1 for r in frows if r["coverage"] == "covered"); pth = sum(1 for r in frows if r["coverage"] == "partial")
        h.append("<h2>%s <span style=\"font-weight:400;color:#666;font-size:12px\">%d requirements · %d covered · %d partial</span></h2>" % (_h.escape(fam), len(frows), c, pth))
        h.append("<table><tr><th>Req.</th><th>Requirement</th><th>Kind</th><th>Coverage</th><th>Evidence class</th><th>Evidence slots</th></tr>")
        for r in frows:
            covtxt = {"covered": "covered", "partial": "partial", "absent": "no evidence yet", "manual": "no automated source; attach Recorded or Stated evidence"}[r["coverage"]]
            h.append("<tr><td class=\"id\">%s</td><td>%s</td><td>%s</td><td class=\"cov-%s\">%s</td><td><span class=\"pill %s\">%s</span></td><td>%s</td></tr>" % (
                _h.escape(r["id"]), _h.escape(r["t"]), _h.escape(r.get("kind") or ""), r["coverage"], covtxt, cls(r), CLASS_LABEL[r["grade"]],
                _h.escape(", ".join(r["sources"]) if r["sources"] else (", ".join(r.get("slots", [])) + " (mapped, no evidence in package)" if r.get("slots") else "—"))))
        h.append("</table>")
    h.append("<p class=\"foot\">Generated by the Beacon Collector (collect, seal, send; never rates). Crosswalk %s. %s Package schema %s. The Value Chain Risk Institute, CC BY 4.0.</p>" % (
        _h.escape(str(fw.get("version", ""))), _h.escape(str(fw.get("status", ""))), _h.escape(str(pkg.get("schema", "?")))))
    h.append("</main></body></html>")
    return "\n".join(h)


def write_bundle(pkg, pkg_path, fw, rows, out_dir):
    """An evidence bundle a third party can open: the sealed package (and blobs if present),
    the coverage report in three forms, and a README that says what it is and how to verify it."""
    import shutil
    os.makedirs(out_dir, exist_ok=True)
    shutil.copy2(pkg_path, os.path.join(out_dir, "package.json"))
    blob_dir = os.path.join(os.path.dirname(os.path.abspath(pkg_path)), "blobs")
    if os.path.isdir(blob_dir):
        dst = os.path.join(out_dir, "blobs")
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        shutil.copytree(blob_dir, dst)
    with open(os.path.join(out_dir, "coverage.json"), "w") as f:
        json.dump(render_json(pkg, fw, rows), f, indent=1)
    with open(os.path.join(out_dir, "coverage.md"), "w") as f:
        f.write(render_md(pkg, fw, rows))
    with open(os.path.join(out_dir, "index.html"), "w") as f:
        f.write(render_html(pkg, fw, rows))
    with open(os.path.join(out_dir, "README.md"), "w") as f:
        f.write("# Evidence bundle: %s\n\n" % fw.get("name", ""))
        f.write("Contents: `package.json` (the sealed evidence package; `blobs/` if raw tool output was captured), `coverage.json`, `coverage.md`, `index.html` (the same coverage report, three forms).\n\n")
        f.write("Verify the seal before trusting anything here: `python3 collector.py verify package.json` (or `beaconlib.verify_package`). A tampered package fails closed.\n\n")
        f.write("This bundle shows where sealed evidence speaks to each requirement and the class of that evidence. %s\n" % " ".join(fw.get("not_this", [])))
    return out_dir


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("package")
    ap.add_argument("--framework", default="cra-annex-i", choices=list(FRAMEWORKS))
    ap.add_argument("--md")
    ap.add_argument("--html")
    ap.add_argument("--json")
    ap.add_argument("--bundle", help="write an evidence bundle directory (package + coverage in md/json/html + README)")
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
    if a.html:
        open(a.html, "w").write(render_html(pkg, fw, rows))
        print("html -> " + a.html)
    if a.json:
        json.dump(render_json(pkg, fw, rows), open(a.json, "w"), indent=1)
        print("json -> " + a.json)
    if a.bundle:
        print("bundle -> " + write_bundle(pkg, a.package, fw, rows, a.bundle))
    # console summary
    cov = sum(1 for r in rows if r["coverage"] == "covered")
    print("%s vs %s: %d/%d controls covered" % (
        pkg.get("subject", {}).get("name", "subject"), fw["name"], cov, len(rows)))
    for r in rows:
        print("  %-7s %-34s %-8s %s" % (r["id"], r["t"][:34], r["coverage"], r["grade"]))
    print("  (indicative, evidence-backed, NOT a certification; NO score)")


if __name__ == "__main__":
    main()
