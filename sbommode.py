#!/usr/bin/env python3
"""
sbommode.py, Beacon Collector adapter: SBOM ingestion (CycloneDX JSON, SPDX JSON).

An SBOM is the vendor's own DECLARATION of what its software contains, produced
at build time. It is sealed as exactly that: epistemic="subject_claim" (Stated
class), verified_by_collector=false. The collector verifies the file's integrity
(hash) and that it parses; it does not verify that the software contains what
the SBOM says. Comparing the declaration against what actually runs is the job of
the runtime observation module (SPEC-runtime-observation-module-v0.1.md), which
will produce Observed evidence for the same slot.

Slot: technology-v1:1.1a (inventory / SBOM / provenance). Observation keys follow
collector.py's scanner item so the scorer's existing rule reads them.

  sbommode.py collect --sbom bom.json [--subject NAME] [--no-anchor] [--out-dir out-sbom]
  sbommode.py verify out-sbom/package.json

Stdlib only. No score.
"""
import argparse
import json
import os
import sys

import adapterkit as ak
import beaconlib as bl

SLOT = "technology-v1:1.1a"


def _purl_type(purl):
    if isinstance(purl, str) and purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0].lower()
    return None


def _walk_cdx(components):
    for c in components or []:
        yield c
        yield from _walk_cdx(c.get("components"))


def parse_cyclonedx(doc):
    comps = list(_walk_cdx(doc.get("components")))
    rows = [{"purl": c.get("purl"), "hashes": bool(c.get("hashes")),
             "license": bool(c.get("licenses")),
             "supplier": bool(c.get("supplier") or c.get("publisher") or c.get("author"))} for c in comps]
    meta = doc.get("metadata") or {}
    tools = meta.get("tools") or []
    if isinstance(tools, dict):  # CycloneDX 1.5+: {"components": [...], "services": [...]}
        tools = (tools.get("components") or []) + (tools.get("services") or [])
    top = meta.get("component") or {}
    return rows, {"format": "CycloneDX", "spec_version": doc.get("specVersion"),
                  "created": meta.get("timestamp"),
                  "tools": sorted({t.get("name", "?") for t in tools if isinstance(t, dict)}),
                  "describes": {"name": top.get("name"), "version": top.get("version")},
                  "embedded_signature_block": "signature" in doc}


def parse_spdx(doc):
    pkgs = doc.get("packages") or []
    rows = []
    for p in pkgs:
        purl = next((r.get("referenceLocator") for r in p.get("externalRefs") or []
                     if r.get("referenceType") == "purl"), None)
        lic = p.get("licenseConcluded") or p.get("licenseDeclared")
        rows.append({"purl": purl, "hashes": bool(p.get("checksums")),
                     "license": bool(lic) and lic not in ("NOASSERTION", "NONE"),
                     "supplier": bool(p.get("supplier")) and p.get("supplier") != "NOASSERTION"})
    ci = doc.get("creationInfo") or {}
    described = doc.get("documentDescribes") or []
    return rows, {"format": "SPDX", "spec_version": doc.get("spdxVersion"),
                  "created": ci.get("created"),
                  "tools": sorted(c.split(":", 1)[1].strip() for c in ci.get("creators") or []
                                  if c.startswith("Tool:")),
                  "describes": {"name": doc.get("name"), "spdx_ids": described},
                  "embedded_signature_block": False}


def detect(doc):
    if isinstance(doc, dict) and doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if isinstance(doc, dict) and str(doc.get("spdxVersion", "")).startswith("SPDX-"):
        return "spdx"
    return None


def observe(doc):
    kind = detect(doc)
    if kind is None:
        raise ValueError("not a CycloneDX JSON or SPDX JSON document")
    rows, meta = (parse_cyclonedx if kind == "cyclonedx" else parse_spdx)(doc)
    n = len(rows)
    types = sorted({t for t in (_purl_type(r["purl"]) for r in rows) if t})
    return {
        "package_inventory": {"present": n > 0, "count": n, "ecosystems": types,
                              "with_purl": sum(1 for r in rows if r["purl"]),
                              "with_hash": sum(1 for r in rows if r["hashes"]),
                              "with_license": sum(1 for r in rows if r["license"]),
                              "with_supplier": sum(1 for r in rows if r["supplier"])},
        "sbom": {"present": True, "standalone": True, **meta,
                 "note": "a standalone SBOM file DECLARED by the subject; contents not verified against the running system"},
        "signed_attestation": {"present": False,
                               "note": "no signature verified by this adapter (an embedded CycloneDX signature block, if any, is "
                                       "recorded above but not checked; Sigstore/SLSA verification is a separate adapter)"},
    }, meta


def collect(args):
    if not os.path.exists(args.sbom):
        sys.exit("SBOM file not found: %s" % args.sbom)
    raw = open(args.sbom, "rb").read()
    try:
        obs, meta = observe(json.loads(raw))
    except (ValueError, json.JSONDecodeError) as e:
        sys.exit("cannot ingest SBOM: %s" % e)
    now = bl.utcnow()
    os.makedirs(args.out_dir, exist_ok=True)
    raw_hash = ak.write_blob(args.out_dir, raw)
    item = ak.make_item(
        SLOT, "document", "subject_claim", False,
        {"tool": "sbom-ingest", "kind": "sbom:" + meta["format"].lower(), "document_name": os.path.basename(args.sbom)},
        {"box": args.box or ("sbom:" + os.path.basename(args.sbom)), "access": "vendor-supplied-file"},
        None, obs, raw_hash, now,
        ak.freshness(now, meta.get("created"), "the SBOM's own creation time governs age"),
        ak.mapped("slot technology-v1:1.1a (inventory/SBOM), same observation keys as scanner mode"))
    subject = {"name": args.subject or "unknown", "scope": "sbom:" + meta["format"].lower(), "collected_utc": now}
    collector = {"name": "beacon-sbom-adapter", "version": "0.1.0", "platform": "any"}
    package, out_path = ak.seal_write(args, [item], subject, collector)
    inv = obs["package_inventory"]
    print("ingested %s %s (%s), sha256 %s..." % (meta["format"], meta.get("spec_version"),
                                                  os.path.basename(args.sbom), raw_hash[:12]))
    print("  %d components declared; with purl %d, hash %d, license %d, supplier %d; ecosystems: %s" % (
        inv["count"], inv["with_purl"], inv["with_hash"], inv["with_license"], inv["with_supplier"],
        ", ".join(inv["ecosystems"]) or "-"))
    ak.summarize([item], package, out_path)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--sbom", required=True)
    ak.add_common(c, "out-sbom")
    ak.add_verify(sub)
    a = ap.parse_args()
    (collect if a.cmd == "collect" else ak.cmd_verify)(a)
