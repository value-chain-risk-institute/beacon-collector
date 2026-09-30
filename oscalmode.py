#!/usr/bin/env python3
"""
oscalmode.py, Beacon Collector adapter: OSCAL JSON import (SSP, Assessment Results, POA&M).

  System Security Plan      the organization's own description of how it implements
                            each control: epistemic="subject_claim" (Stated).
  Assessment Results        an assessor's findings per control objective:
                            epistemic="third_party_attestation" (Attested), with the
                            OSCAL origin actor types (tool / assessment-platform / party)
                            and observation methods (EXAMINE / INTERVIEW / TEST) kept
                            per finding. --self-assessed relabels as subject_claim when
                            the organization assessed itself.
  POA&M                     the organization's own list of open weaknesses:
                            epistemic="subject_claim", observation marked
                            polarity="open_gap" (this is evidence of a GAP, not coverage).

NIST SP 800-53 control ids are mapped to existing slots through NIST80053_CROSSWALK
below (same style as docs.py's SOC 2 crosswalk: indicative, versioned, arguable).
Controls it does not list go to one "unmapped" item; no slot id is invented.
JSON only: OSCAL XML and YAML are out of scope (convert with NIST's oscal-cli first).

  oscalmode.py collect --oscal FILE.json [--self-assessed] [--subject NAME]
  oscalmode.py verify out-oscal/package.json
"""
import argparse
import json
import os
import sys

import adapterkit as ak
import beaconlib as bl

CROSSWALK_VERSION = "vcri.crosswalk.nist-sp800-53r5-to-beacon-slots/0.1 (indicative, 2026-09-30)"
NIST80053_CROSSWALK = {
    "ac-2": ["people-v1:jml"], "ps-4": ["people-v1:jml"],
    "ac-6": ["people-v1:least-privilege"],
    "ia-2": ["technology-v1:2.2a"], "ia-2.1": ["people-v1:mfa"], "ia-2.2": ["people-v1:mfa"],
    "cm-2": ["technology-v1:1.1b"], "cm-6": ["technology-v1:1.1b"],
    "cm-8": ["technology-v1:1.1a"], "cm-3": ["process-v1:change-management"],
    "ra-5": ["technology-v1:4.4a"], "si-2": ["technology-v1:4.4a"],
    "si-3": ["technology-v1:4.4b"], "sc-7": ["technology-v1:4.4c"],
    "sc-8": ["data-v1:in-transit"],
    "au-6": ["technology-v1:6.6a"], "si-4": ["technology-v1:6.6a"],
    "ir-4": ["process-v1:incident-response"],
    "sa-11": ["technology-v1:6.6c"], "ca-2": ["process-v1:control-effectiveness"],
    "cp-9": ["data-v1:backup-recovery"], "si-12": ["data-v1:retention"],
}
KINDS = {"system-security-plan": "ssp", "assessment-results": "ar", "plan-of-action-and-milestones": "poam"}


def control_of(target_id):
    """'ac-6.1_obj' / 'ac-2_smt.a' / 'AC-2(1)' -> 'ac-6.1' / 'ac-2' / 'ac-2.1'."""
    c = (target_id or "").split("_", 1)[0].strip().lower()
    return c.replace("(", ".").replace(")", "")


def slots_for(cid):
    return NIST80053_CROSSWALK.get(cid) or NIST80053_CROSSWALK.get(cid.split(".", 1)[0]) or []


def _texts(node):
    for bc in node.get("by-components") or []:
        if bc.get("description"):
            yield bc["description"]


def ssp_records(doc):
    out = []
    for ir in (doc.get("control-implementation") or {}).get("implemented-requirements") or []:
        texts = list(_texts(ir))
        for st in ir.get("statements") or []:
            texts += list(_texts(st))
        out.append((control_of(ir.get("control-id")), {
            "statements": len(ir.get("statements") or []), "by_component_texts": len(texts),
            "excerpt": (texts[0][:240] if texts else None), "texts_sha256": bl.sha256("\n".join(texts).encode())}))
    return out


def ar_records(doc):
    out = []
    for res in doc.get("results") or []:
        obs = {o.get("uuid"): o for o in res.get("observations") or []}
        for f in res.get("findings") or []:
            t = f.get("target") or {}
            rel = [obs.get(r.get("observation-uuid"), {}) for r in f.get("related-observations") or []]
            actors = sorted({a.get("type") for src in [f] + rel for o in src.get("origins") or []
                             for a in o.get("actors") or [] if a.get("type")})
            out.append((control_of(t.get("target-id")), {
                "title": f.get("title"), "target": t.get("target-id"),
                "state": (t.get("status") or {}).get("state"),
                "methods": sorted({m for o in rel for m in o.get("methods") or []}),
                "origin_actor_types": actors or ["unspecified"], "result": res.get("title")}))
    return out


def poam_records(doc):
    findings = {f.get("uuid"): f for f in doc.get("findings") or []}
    out = []
    for p in doc.get("poam-items") or []:
        ctl = [control_of((findings.get(r.get("finding-uuid"), {}).get("target") or {}).get("target-id"))
               for r in p.get("related-findings") or []]
        for c in [c for c in ctl if c] or [""]:
            out.append((c, {"uuid": p.get("uuid"), "title": p.get("title")}))
    return out


SPEC = {  # kind -> (records fn, obs key, epistemic, polarity)
    "ssp": (ssp_records, "declared", "subject_claim", "coverage_claim"),
    "ar": (ar_records, "attested", "third_party_attestation", "assessment"),
    "poam": (poam_records, "open_poam_items", "subject_claim", "open_gap"),
}


def observe(root, self_assessed=False):
    kinds = [k for k in KINDS if k in root]
    if len(kinds) != 1:
        raise ValueError("expected exactly one of %s at the JSON root" % ", ".join(KINDS))
    kind = KINDS[kinds[0]]
    doc = root[kinds[0]]
    fn, key, epistemic, polarity = SPEC[kind]
    if kind == "ar" and self_assessed:
        epistemic = "subject_claim"
    grouped = {}
    for cid, rec in fn(doc):
        for slot in slots_for(cid) if cid else []:
            grouped.setdefault(slot, []).append((cid, rec))
        if not cid or not slots_for(cid):
            grouped.setdefault(ak.UNMAPPED, []).append((cid or "(no control id)", rec))
    obs = {}
    for slot, recs in grouped.items():
        o = {"present": True, "polarity": polarity, "source_controls": sorted({c for c, _ in recs}),
             "records": [{"control": c, **r} for c, r in recs][:300], "record_count": len(recs)}
        if kind == "ar":
            o["satisfied"] = sum(1 for _, r in recs if r["state"] == "satisfied")
            o["not_satisfied"] = sum(1 for _, r in recs if r["state"] == "not-satisfied")
            o["note"] = "the assessor ASSERTS these findings; relayed, not re-observed by the collector"
        obs[slot] = o
    meta = doc.get("metadata") or {}
    return kind, key, epistemic, obs, {"title": meta.get("title"), "oscal_version": meta.get("oscal-version"),
                                       "last_modified": meta.get("last-modified"), "uuid": doc.get("uuid")}


def collect(args):
    raw = open(args.oscal, "rb").read()
    try:
        kind, key, epistemic, obs, meta = observe(json.loads(raw), args.self_assessed)
    except (ValueError, json.JSONDecodeError) as e:
        sys.exit("cannot ingest OSCAL: %s" % e)
    now = bl.utcnow()
    os.makedirs(args.out_dir, exist_ok=True)
    raw_hash = ak.write_blob(args.out_dir, raw)
    src = {"tool": "oscal-" + kind, "kind": "oscal_json", "document_name": os.path.basename(args.oscal), **meta}
    prov = {"box": args.box or ("oscal:" + os.path.basename(args.oscal)), "access": "organization-supplied-file"}
    fresh = ak.freshness(now, meta["last_modified"], "the OSCAL document's last-modified governs age")
    items = [ak.make_item(slot, "document", epistemic, False, src, prov, key, obs[slot], raw_hash, now, fresh,
                          ak.unmapped("controls (listed in source_controls) not in the indicative 800-53 crosswalk, or records with no control id", [])
                          if slot == ak.UNMAPPED else ak.mapped(CROSSWALK_VERSION))
             for slot in sorted(obs)]
    if not items:
        print("warning: no controls or findings found; nothing to seal")
        return
    subject = {"name": args.subject or meta.get("title") or "unknown", "scope": "oscal:" + kind, "collected_utc": now}
    collector = {"name": "beacon-oscal-adapter", "version": "0.1.0", "platform": "any"}
    package, out_path = ak.seal_write(args, items, subject, collector)
    print("ingested OSCAL %s %r (oscal %s), sha256 %s..." % (kind, meta["title"], meta["oscal_version"], raw_hash[:12]))
    ak.summarize(items, package, out_path)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--oscal", required=True)
    c.add_argument("--self-assessed", action="store_true",
                   help="the organization assessed itself: label Assessment Results as subject_claim")
    ak.add_common(c, "out-oscal")
    ak.add_verify(sub)
    a = ap.parse_args()
    (collect if a.cmd == "collect" else ak.cmd_verify)(a)
