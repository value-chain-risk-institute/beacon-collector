#!/usr/bin/env python3
"""
adapterkit.py, shared plumbing for the file/API adapters added 2026-09-30
(sbommode, scorecardmode, outsidein, exportcsv, oscalmode).

The trust math is NOT here: sealing, signing, verifying and anchoring stay in
beaconlib (one implementation for every mode). This file only removes the
copy-paste every existing mode carries: write the raw artifact as a hashed blob,
build an item in the house shape, seal + write + anchor, and the verify CLI.

Mapping rule for every adapter: an item's `subcriterion` is either a slot the
scorer evidence map already knows, or the reserved value "unmapped". An unmapped
item carries `mapping.status = "unmapped"`, the reason, and the rubric keys a
methodology decision could give it a home under. score.py reports it as a gap
("slot not in the evidence map"); nothing invents a slot id.
"""
import json
import os
import sys
from datetime import datetime, timezone

import beaconlib as bl

UNMAPPED = "unmapped"


def write_blob(out_dir: str, raw: bytes) -> str:
    """Store the raw artifact verbatim under blobs/, named by its sha256 (the
    `.json` suffix is the verifier's naming convention, whatever the content)."""
    h = bl.sha256(raw)
    blob_dir = os.path.join(out_dir, "blobs")
    os.makedirs(blob_dir, exist_ok=True)
    path = os.path.join(blob_dir, "sha256-" + h + ".json")
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(raw)
    return h


def _parse_ts(s):
    if not s or not isinstance(s, str):
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def freshness(now: str, evidence_date: str = None, note: str = "", live: bool = False) -> dict:
    """Evidence age is the SOURCE's date when it has one (an SBOM's timestamp, a
    Scorecard run date, an OSCAL last-modified), never the ingest date. A live
    check is age 0; a file with no date of its own has an unknown age (None)."""
    out = {"collected_utc": now, "evidence_date": now if live else evidence_date,
           "evidence_age_seconds": 0 if live else None, "note": note}
    a, b = _parse_ts(evidence_date), _parse_ts(now)
    if not live and a and b:
        out["evidence_age_seconds"] = max(0, int((b - a).total_seconds()))
    return out


def mapped(via: str) -> dict:
    return {"status": "mapped", "via": via}


def unmapped(reason: str, candidates: list) -> dict:
    return {"status": "unmapped", "reason": reason, "candidate_rubric_keys": candidates,
            "note": "no slot in the scorer evidence map; score.py reports this as a gap"}


def make_item(slot, mode, epistemic, verified, source, provenance, obs_key, obs,
              raw_hash, now, fresh, mapping) -> dict:
    # obs_key=None: `obs` already is the full observation (several keyed facts, as
    # scanner mode emits them for 1.1a); otherwise it is wrapped under obs_key.
    observation = obs if obs_key is None else {obs_key: obs}
    expected = [k for k, v in observation.items() if isinstance(v, dict)]
    return {
        "subcriterion": slot,
        "mode": mode,
        "source": {**source, "raw_sha256": raw_hash},
        "provenance": provenance,
        "observation": observation,
        "epistemic": epistemic,
        "verified_by_collector": verified,
        "mapping": mapping,
        "context": [],
        "completeness": bl.completeness(observation, expected),
        "freshness": fresh,
        "artifact_ref": "blob/sha256-" + raw_hash,
        "collected_utc": now,
    }


def seal_write(args, items, subject, collector):
    core = bl.build_package(subject, collector, items)
    try:
        package = bl.seal_and_sign(core, sign=args.sign, home=args.home)
    except RuntimeError as e:
        sys.exit(str(e))
    out_path = os.path.join(args.out_dir, "package.json")
    with open(out_path, "w") as f:
        f.write(json.dumps(package, indent=2))
    bl.anchor_after_write(out_path, sealed_utc=subject.get("collected_utc"), home=args.home,
                          enabled=not args.no_anchor)
    return package, out_path


def summarize(items, package, out_path):
    for it in items:
        print("  %-34s epistemic=%s%s" % (it["subcriterion"], it["epistemic"],
              "  (gap: %s)" % it["mapping"]["reason"][:70] if it["mapping"]["status"] == "unmapped" else ""))
    print("  sealed -> %s  |  package_hash %s  |  NO score." % (out_path, package["seal"]["package_hash"][:16]))


def add_common(c, default_out):
    c.add_argument("--subject")
    c.add_argument("--box", help="provenance label for where this evidence came from")
    c.add_argument("--sign", action="store_true")
    c.add_argument("--no-anchor", action="store_true",
                   help="seal only; do not timestamp/anchor the package (state recorded as unanchored)")
    c.add_argument("--home", default=os.path.expanduser("~/.beacon"))
    c.add_argument("--out-dir", default=default_out)


def add_verify(sub):
    v = sub.add_parser("verify")
    v.add_argument("package")
    v.add_argument("--registry")
    v.add_argument("--blobs")
    v.add_argument("--withheld", action="append", metavar="RAW_SHA256")


def cmd_verify(args):
    pkg = json.load(open(args.package))
    blob_dir = args.blobs or os.path.join(os.path.dirname(os.path.abspath(args.package)), "blobs")
    ok = bl.verify_package(pkg, blob_dir=blob_dir, registry=args.registry, withheld=args.withheld)
    sys.exit(0 if ok else 1)
