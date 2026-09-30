#!/usr/bin/env python3
"""Tests for the open reference scorer (score.py).

Run: python test_score.py

Claims under test:
  - fail closed: a package that does not verify is refused, exit 2;
  - the arithmetic is the questionnaire's (sum of dim.weight * sum(sub.weight * level));
  - evidence class is the ceiling (attested never exceeds 2, stated never exceeds 1,
    observed never exceeds 4, level 5 never appears);
  - observed beats attested on the same subcriterion and the disagreement is a
    reported contradiction, not an average;
  - a slot with no rubric home is a reported gap, never a silent drop.
"""
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import contextlib

import beaconlib as bl
import score as sc

HERE = os.path.dirname(os.path.abspath(__file__))
fails = []


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def item(slot, epistemic, observation, mode="export"):
    return {"subcriterion": slot, "mode": mode, "epistemic": epistemic,
            "verified_by_collector": epistemic != "third_party_attestation",
            "observation": observation, "collected_utc": "2026-09-12T20:00:00+00:00",
            "completeness": {"expected": [], "obtained": [], "fraction": 1.0}}


def build(items):
    core = bl.build_package({"name": "t", "scope": "s", "collected_utc": "2026-09-12T20:00:00+00:00"},
                            {"name": "beacon-test", "version": "0"}, copy.deepcopy(items))
    return bl.seal_and_sign(core, sign=False, home="/nonexistent")


def main():
    emap = json.load(open(os.path.join(HERE, "scorer-evidence-map-v0.json")))
    ids = json.load(open(os.path.join(HERE, "rubrics", "index.json")))
    rubrics = {rid: json.load(open(os.path.join(HERE, "rubrics", rid + ".json"))) for rid in ids}
    people = rubrics["people-v1"]
    dim2 = [d for d in people["dimensions"] if d["n"] == 2][0]
    w2a = [s for s in dim2["subcriteria"] if s["key"] == "2a"][0]["weight"]

    print("arithmetic matches the questionnaire")
    pkg = build([item("people-v1:mfa", "observed_export", {"mfa": {"coverage_fraction": 1.0}})])
    out = sc.score_package(pkg, rubrics, emap)
    r = out["rubrics"]["people-v1"]
    lvl = [s for d in r["dimensions"] if d["n"] == 2 for s in d["subcriteria"] if s["key"] == "2a"][0]["level"]
    check("100% observed MFA coverage -> level 4 (observed cap), not 5", lvl == 4)
    expected_comparable = dim2["weight"] * (w2a * 4)
    check("comparable score = dim.weight * sub.weight * level with everything else 0",
          abs(r["score_comparable"] - round(expected_comparable, 3)) < 1e-6)
    check("covered score renormalises to the level itself when one sub is scored", r["score_covered"] == 4.0)
    check("coverage reported as 1 of 18", r["subcriteria_scored"] == 1 and r["subcriteria_total"] == 18)
    check("level 5 never awarded", not any(s["level"] == 5 for rr in out["rubrics"].values()
                                            for d in rr["dimensions"] for s in d["subcriteria"]))

    print("evidence class is the ceiling")
    pkg = build([item("people-v1:mfa", "third_party_attestation", {"attested": {"present": True}}, mode="document")])
    out = sc.score_package(pkg, rubrics, emap)
    # the mfa slot's rule is a fraction ladder, which a document never carries; an
    # attestation must still score AS an attestation (cap 2), never be dropped.
    lvl = [s for d in out["rubrics"]["people-v1"]["dimensions"] for s in d["subcriteria"] if s["key"] == "2a"][0]["level"]
    check("a SOC 2 attesting MFA scores attested level 2 on the ladder-ruled slot", lvl == 2)
    # And the cap on a slot whose native rule is attested_present:
    pkg = build([item("technology-v1:2.2a", "third_party_attestation", {"attested": {"present": True}}, mode="document")])
    out = sc.score_package(pkg, rubrics, emap)
    lvl = [s for d in out["rubrics"]["technology-v1"]["dimensions"] for s in d["subcriteria"] if s["key"] == "2a"][0]["level"]
    check("attested_present rule gives 2 and the class cap holds", lvl == 2)
    pkg = build([item("technology-v1:2.2a", "subject_claim", {"attested": {"present": True}}, mode="document")])
    out = sc.score_package(pkg, rubrics, emap)
    lvl = [s for d in out["rubrics"]["technology-v1"]["dimensions"] for s in d["subcriteria"] if s["key"] == "2a"][0]["level"]
    check("a subject's own claim caps at 1", lvl == 1)

    print("observed beats attested, contradiction reported")
    # people-v1:mfa has a ladder rule (needs a fraction), so build the contradiction on
    # technology-v1:1.1b where the scanner observes zero checks and a document attests.
    pkg = build([
        item("technology-v1:1.1b", "third_party_attestation", {"attested": {"present": True}}, mode="document"),
        item("technology-v1:1.1b", "observed_scan", {"checks_evaluated": {"present": True, "passed": 0, "failed": 3}}, mode="scanner"),
    ])
    out = sc.score_package(pkg, rubrics, emap)
    sub = [s for d in out["rubrics"]["technology-v1"]["dimensions"] for s in d["subcriteria"] if s["key"] == "1b"][0]
    check("observed item chosen over attested", sub["evidence"]["class"] == "observed")
    check("observed level 2 (checks ran, some failed) stands even though attestation raw is also 2; no false contradiction",
          sub["level"] == 2 and not out["contradictions"])
    pkg = build([
        item("technology-v1:1.1b", "third_party_attestation", {"attested": {"present": True}}, mode="document"),
        item("technology-v1:1.1b", "observed_scan", {"checks_evaluated": {"present": False}}, mode="scanner"),
    ])
    out = sc.score_package(pkg, rubrics, emap)
    sub = [s for d in out["rubrics"]["technology-v1"]["dimensions"] for s in d["subcriteria"] if s["key"] == "1b"][0]
    check("scanner observed no checks -> level 0 wins over the attestation's 2", sub["level"] == 0)
    check("contradiction reported", len(out["contradictions"]) == 1 and out["contradictions"][0]["key"] == "1b")

    print("the killer demo: SOC 2 says MFA everywhere, the IdP export shows 30%")
    pkg = build([
        item("people-v1:mfa", "third_party_attestation", {"attested": {"present": True}}, mode="document"),
        item("people-v1:mfa", "observed_export", {"mfa": {"coverage_fraction": 0.3}}),
    ])
    out = sc.score_package(pkg, rubrics, emap)
    sub = [s for d in out["rubrics"]["people-v1"]["dimensions"] for s in d["subcriteria"] if s["key"] == "2a"][0]
    check("observed 30% -> level 1 wins over the attestation's 2", sub["level"] == 1 and sub["evidence"]["class"] == "observed")
    check("contradiction reported on people-v1/2a", any(c["key"] == "2a" for c in out["contradictions"]))

    print("gaps are reported, never dropped")
    pkg = build([item("process-v1:incident-response", "third_party_attestation", {"attested": {"present": True}}, mode="document"),
                 item("made-up-v1:nothing", "observed_export", {"x": 1})])
    out = sc.score_package(pkg, rubrics, emap)
    check("two gaps: no rubric home, and unknown slot", len(out["gaps"]) == 2)
    check("nothing scored from gap items", not out["rubrics"])

    print("adverse attestations earn no credit (fix 2026-09-30)")
    pkg = build([item("technology-v1:1.1a", "third_party_attestation",
                      {"attested": {"present": True, "satisfied": 0, "not_satisfied": 2}}, mode="oscal")])
    out = sc.score_package(pkg, rubrics, emap)
    check("OSCAL not-satisfied findings score nothing", not out["rubrics"])
    pkg = build([item("technology-v1:1.1a", "third_party_attestation",
                      {"attested": {"present": True, "checks": {"Vulnerabilities": {"third_party_check_score_0_10": 0, "inconclusive": False}}}}, mode="scorecard")])
    out = sc.score_package(pkg, rubrics, emap)
    check("Scorecard check at 0/10 scores nothing", not out["rubrics"])

    print("least-privilege export is scored (fix 2026-09-30)")
    pkg = build([item("people-v1:least-privilege", "observed_export",
                      {"least-privilege": {"present": True, "privileged_fraction": 0.03}})])
    out = sc.score_package(pkg, rubrics, emap)
    check("least-privilege observation reaches people-v1", "people-v1" in out["rubrics"])

    print("fail closed via the CLI")
    tmp = tempfile.mkdtemp()
    pkg = build([item("people-v1:mfa", "observed_export", {"mfa": {"coverage_fraction": 0.9}})])
    path = os.path.join(tmp, "package.json")
    json.dump(pkg, open(path, "w"))
    r = subprocess.run([sys.executable, os.path.join(HERE, "score.py"), path], capture_output=True, text=True)
    check("valid package scores (exit 0)", r.returncode == 0 and "people-v1" in r.stdout)
    pkg["items"][0]["observation"]["mfa"]["coverage_fraction"] = 1.0
    json.dump(pkg, open(path, "w"))
    r = subprocess.run([sys.executable, os.path.join(HERE, "score.py"), path], capture_output=True, text=True)
    check("tampered package refused (exit 2, REFUSED)", r.returncode == 2 and "REFUSED" in r.stdout)

    print("\n%d checks failed" % len(fails))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
