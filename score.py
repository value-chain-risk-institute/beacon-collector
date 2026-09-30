#!/usr/bin/env python3
"""score.py, the open reference scorer: reads a sealed evidence package, emits the
free-tier score (SPEC 0.9: "the other side of the schema exists").

  score.py PACKAGE.json [--rubrics DIR] [--map scorer-evidence-map-v0.json]
                        [--registry DIR] [--blobs DIR] [--json OUT.json]

Rules of the house, in code:
  - Fail closed. The package is verified first (every hash, the merkle root, the
    signature when present). An invalid package is not scored.
  - Same arithmetic as the questionnaire (Website/scorer/app.js): dimension score
    = sum(sub.weight * level), rubric score P = sum(dim.weight * dimension score),
    unscored subcriteria count as 0. That is the COMPARABLE score. The COVERED
    score renormalises over scored subcriteria only and is printed beside the
    coverage percentage so nobody mistakes sparse evidence for a bad posture.
  - Leveling is not this file's opinion. Every rule lives in the evidence map
    (VCRI's, versioned, public). This file applies them and shows its work.
  - Evidence class is the ceiling (observed 4, attested 2, stated 1). Level 5 is
    never awarded here. Observed beats attested on the same subcriterion, and the
    disagreement is reported as a contradiction rather than averaged away.
  - Collector slots with no home in the rubric are reported as gaps.
"""
import argparse
import io
import json
import os
import sys
import contextlib

import beaconlib as bl

HERE = os.path.dirname(os.path.abspath(__file__))
CLASS_RANK = {"observed": 3, "attested": 2, "stated": 1, "unknown": 0}


def load(path):
    with open(path) as f:
        return json.load(f)


def get_path(obj, dotted):
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def item_class(item, emap):
    epi = item.get("epistemic")
    cls = emap["epistemic_to_class"].get(epi)
    if cls:
        return cls
    if item.get("mode") == "scanner":
        # scanner packages sealed before 2026-09-12 carry no item-level label; a
        # scanner item is by construction something a tool observed on the target
        return "observed"
    return "unknown"


def apply_rule(rule, observation, emap):
    """Return (level or None, explanation)."""
    t = rule.get("type")
    if t == "attested_present":
        present = get_path(observation, "attested.present")
        if not present:
            return None, "no attestation in observation"
        # An attestation that reports failure is adverse evidence, not credit.
        # OSCAL assessment results carry satisfied/not_satisfied counts; OpenSSF
        # Scorecard relays per-check 0-10 scores (-1 = inconclusive).
        not_sat = get_path(observation, "attested.not_satisfied")
        if isinstance(not_sat, int) and not_sat > 0:
            return None, "attestation reports %d not-satisfied finding(s)" % not_sat
        checks = get_path(observation, "attested.checks")
        if isinstance(checks, dict):
            scores = [c.get("third_party_check_score_0_10") for c in checks.values()
                      if isinstance(c, dict) and not c.get("inconclusive")]
            scores = [x for x in scores if isinstance(x, (int, float))]
            if scores and min(scores) == 0:
                return None, "third-party check scored 0/10 (%s)" % ", ".join(
                    n for n, c in checks.items() if isinstance(c, dict) and c.get("third_party_check_score_0_10") == 0)
            if scores:
                # Bands are data in the evidence map (provisional cut points), not code.
                full = emap["attested_present_level"]
                mean = sum(scores) / len(scores)
                for cut, band in emap.get("attested_score_bands", {}).get("bands", [[8, "full"], [4, "reduced"]]):
                    if mean >= cut:
                        lvl = full if band == "full" else max(full - 1, 1)
                        return lvl, "third-party checks average %.1f/10 (band >= %s: %s)" % (mean, cut, band)
                return None, "third-party checks average %.1f/10, below the lowest band" % mean
        return emap["attested_present_level"], "attestation present"

    if t == "steps":
        level, why = None, []
        for step in rule["steps"]:
            v = get_path(observation, step["path"])
            ok = False
            if "equals" in step:
                ok = v == step["equals"]
            elif "gt" in step:
                ok = isinstance(v, (int, float)) and v > step["gt"]
            if ok and "requires" in step:
                rv = get_path(observation, step["requires"]["path"])
                ok = isinstance(rv, (int, float)) and rv > step["requires"].get("gt", -1)
            if ok:
                level = max(level or 0, step["level"])
                why.append("%s -> %d" % (step["path"], step["level"]))
        if level is None:
            return 0 if any(get_path(observation, s["path"]) is not None for s in rule["steps"]) else None, \
                "no step satisfied"
        return level, "; ".join(why)

    if t in ("fraction_ladder", "inverse_fraction_ladder"):
        v = get_path(observation, rule["path"])
        if not isinstance(v, (int, float)):
            return None, "%s absent" % rule["path"]
        for threshold, level in rule["ladder"]:
            if (t == "fraction_ladder" and v >= threshold) or (t == "inverse_fraction_ladder" and v <= threshold):
                return level, "%s=%s meets %s" % (rule["path"], v, threshold)
        return rule.get("else", 0), "%s=%s below every rung" % (rule["path"], v)

    if t == "vuln_ladder":
        sev = get_path(observation, rule["path"])
        if not isinstance(sev, dict):
            return None, "no severity table"
        vl = emap["vuln_ladder"]
        total = sum(v for v in sev.values() if isinstance(v, int))
        if total == 0:
            return vl["no_findings"], "no findings on the scanned target"
        if sev.get("CRITICAL", 0) > 0:
            return vl["worst_critical"], "%d critical open" % sev["CRITICAL"]
        if sev.get("HIGH", 0) > 0:
            return vl["worst_high"], "%d high open" % sev["HIGH"]
        return vl["worst_low_or_medium"], "worst open severity is medium or lower"

    return None, "unknown rule type %r" % t


def score_package(pkg, rubrics, emap):
    caps = emap["class_caps"]
    per_sub = {}        # (rubric, key) -> chosen evidence record
    candidates = {}     # (rubric, key) -> all evidence records
    gaps = []
    for item in pkg.get("items", []):
        slot = item.get("subcriterion")
        spec = emap["slots"].get(slot)
        if spec is None:
            gaps.append({"slot": slot, "reason": "slot not in the evidence map"})
            continue
        if spec.get("rubric") is None:
            gaps.append({"slot": slot, "reason": spec.get("gap", "no rubric home")})
            continue
        cls = item_class(item, emap)
        cap = caps.get(cls, 0)
        rule = spec["rule"]
        obs = item.get("observation", {})
        if cls == "attested" and get_path(obs, "attested.present") is not None:
            # An attestation is an attestation whatever the slot's observed-evidence
            # rule expects: a SOC 2 saying "MFA enforced" scores as attested (cap 2)
            # on the MFA subcriterion; it does not become unscorable because the
            # slot's rule wants a coverage fraction that a document never carries.
            rule = {"type": "attested_present"}
        raw, why = apply_rule(rule, obs, emap)
        level = None if raw is None else min(raw, cap)
        rec = {"slot": slot, "class": cls, "cap": cap, "raw_level": raw, "level": level,
               "why": why, "mode": item.get("mode"), "collected_utc": item.get("collected_utc"),
               "item_sha256": item.get("item_sha256")}
        k = (spec["rubric"], spec["key"])
        candidates.setdefault(k, []).append(rec)
    contradictions = []
    for k, recs in candidates.items():
        scored = [r for r in recs if r["level"] is not None]
        if not scored:
            continue
        scored.sort(key=lambda r: (CLASS_RANK.get(r["class"], 0), r["collected_utc"] or ""), reverse=True)
        chosen = scored[0]
        per_sub[k] = chosen
        for other in scored[1:]:
            if other["class"] != chosen["class"] and other["raw_level"] is not None and other["raw_level"] > chosen["level"]:
                contradictions.append({"rubric": k[0], "key": k[1],
                                       "observed": {"slot": chosen["slot"], "level": chosen["level"], "why": chosen["why"]},
                                       "attested": {"slot": other["slot"], "raw_level": other["raw_level"], "why": other["why"]},
                                       "note": "higher evidence class wins; the lower-class item claimed more"})

    out = {"rubrics": {}, "gaps": gaps, "contradictions": contradictions,
           "map_status": emap.get("_status"), "level_5_awarded": False}
    for rid, rubric in rubrics.items():
        dims_out = []
        P_all = 0.0
        covered_num = covered_den = 0.0
        n_sub = n_scored = 0
        any_evidence = False
        for dim in rubric["dimensions"]:
            D = 0.0
            subs = []
            dim_cov_num = dim_cov_den = 0.0
            for sc in dim["subcriteria"]:
                n_sub += 1
                rec = per_sub.get((rid, sc["key"]))
                level = rec["level"] if rec else None
                if level is not None:
                    n_scored += 1
                    any_evidence = True
                    D += sc["weight"] * level
                    dim_cov_num += sc["weight"] * level
                    dim_cov_den += sc["weight"]
                subs.append({"key": sc["key"], "title": sc["title"], "weight": sc["weight"],
                             "level": level, "evidence": rec})
            P_all += dim["weight"] * D
            dim_covered = (dim_cov_num / dim_cov_den) if dim_cov_den else None
            if dim_cov_den:
                covered_num += dim["weight"] * dim_covered
                covered_den += dim["weight"]
            dims_out.append({"n": dim["n"], "name": dim["name"], "weight": dim["weight"],
                             "score_comparable": round(D, 3),
                             "score_covered": None if dim_covered is None else round(dim_covered, 3),
                             "subcriteria": subs})
        if not any_evidence:
            continue
        P_cov = (covered_num / covered_den) if covered_den else None
        grade_cov = grade_for(rubric, P_cov, dims_out, covered=True)
        out["rubrics"][rid] = {
            "title": rubric.get("title"), "scaleMax": rubric.get("scaleMax", 5),
            "coverage_fraction": round(n_scored / n_sub, 3) if n_sub else 0,
            "subcriteria_scored": n_scored, "subcriteria_total": n_sub,
            "score_comparable": round(P_all, 3),
            "score_covered": None if P_cov is None else round(P_cov, 3),
            "grade_covered": grade_cov,
            "dimensions": dims_out,
        }
    return out


def grade_for(rubric, P, dims_out, covered=True):
    if P is None:
        return None
    grade = None
    for g in rubric.get("grades", []):
        if g["min"] <= P <= g["max"] + 1e-9:
            grade = g["grade"]
    hf = rubric.get("hardFail") or {}
    if hf and grade:
        field = "score_covered" if covered else "score_comparable"
        low = [d for d in dims_out if d[field] is not None and d[field] < hf.get("belowDimension", -1)]
        if low and grade < hf.get("capGrade", "Z"):
            grade = hf["capGrade"] + " (capped: %s below %s)" % (", ".join(d["name"] for d in low), hf["belowDimension"])
    return grade


def render(out, pkg_path):
    lines = ["FREE-TIER REFERENCE SCORE (draft rules; see the evidence map). Level 5 is never awarded here.",
             "package: %s" % pkg_path, ""]
    for rid, r in out["rubrics"].items():
        lines.append("== %s: covered %s (grade %s) | comparable %s | coverage %d/%d subcriteria (%d%%)" % (
            rid, r["score_covered"], r["grade_covered"], r["score_comparable"],
            r["subcriteria_scored"], r["subcriteria_total"], round(100 * r["coverage_fraction"])))
        for d in r["dimensions"]:
            scored = [s for s in d["subcriteria"] if s["level"] is not None]
            if not scored:
                continue
            lines.append("   %s %-12s covered %s" % (d["n"], d["name"], d["score_covered"]))
            for s in scored:
                e = s["evidence"]
                lines.append("      %-3s L%d  %-48s [%s, cap %d] %s" % (
                    s["key"], s["level"], s["title"][:48], e["class"], e["cap"], e["why"]))
    if out["contradictions"]:
        lines.append("")
        lines.append("CONTRADICTIONS (observed fact vs attestation on the same subcriterion):")
        for c in out["contradictions"]:
            lines.append("   %s/%s: %s observed L%d (%s) vs %s attested raw L%d (%s)" % (
                c["rubric"], c["key"], c["observed"]["slot"], c["observed"]["level"], c["observed"]["why"],
                c["attested"]["slot"], c["attested"]["raw_level"], c["attested"]["why"]))
    if out["gaps"]:
        lines.append("")
        lines.append("GAPS (evidence with no home in the rubric; a methodology decision, not a scorer bug):")
        for g in out["gaps"]:
            lines.append("   %s: %s" % (g["slot"], g["reason"]))
    if not out["rubrics"]:
        lines.append("no scorable evidence in this package")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("package")
    ap.add_argument("--rubrics", default=os.path.join(HERE, "rubrics"))
    ap.add_argument("--map", default=os.path.join(HERE, "scorer-evidence-map-v0.json"))
    ap.add_argument("--registry")
    ap.add_argument("--blobs")
    ap.add_argument("--json", help="also write the full result here")
    ap.add_argument("--skip-verify", action="store_true", help="TESTING ONLY; scoring an unverified package is not a score")
    a = ap.parse_args()

    pkg = load(a.package)
    if not a.skip_verify:
        blob_dir = a.blobs or os.path.join(os.path.dirname(os.path.abspath(a.package)), "blobs")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ok = bl.verify_package(pkg, blob_dir=blob_dir, registry=a.registry)
        if not ok:
            print("REFUSED: package does not verify; not scoring.\n" + buf.getvalue().strip())
            sys.exit(2)
    emap = load(a.map)
    ids = load(os.path.join(a.rubrics, "index.json"))
    rubrics = {rid: load(os.path.join(a.rubrics, rid + ".json")) for rid in ids
               if os.path.isfile(os.path.join(a.rubrics, rid + ".json"))}
    out = score_package(pkg, rubrics, emap)
    out["package_hash"] = pkg.get("seal", {}).get("package_hash")
    out["verified"] = not a.skip_verify
    print(render(out, a.package))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(out, f, indent=2)
    sys.exit(0)


if __name__ == "__main__":
    main()
