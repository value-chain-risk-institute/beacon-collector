#!/usr/bin/env python3
"""
merge.py, Beacon Collector 0.4: multi-box aggregation.

Proves the multi-box half of 0.4. A real subject is an ESTATE: a DC host, a
cloud account, an office endpoint, each collected separately (different access,
different times), each producing its own sealed single-box package. merge.py
unions those into ONE package the subject sends as a whole, WITHOUT losing which
box each piece of evidence came from.

Trust properties preserved:
  - Every item keeps its own item_sha256 and its `provenance.box`. Merge never
    rewrites an item's evidence; it only collects items into a new package and
    re-seals + (optionally) re-signs the aggregate. Editing any item still fails
    item verification; the aggregate seal binds the whole set.
  - Exact-duplicate items (same item_sha256) are collapsed once, so re-merging is
    idempotent. Two DIFFERENT boxes reporting the same slot are BOTH kept (they
    have different provenance -> different item_sha256): the scorer sees per-box
    coverage, not a silently-deduplicated single claim.
  - Subject mismatch across inputs is refused (you do not merge Acme's DC box
    with Beta's cloud box into one subject by accident).
  - Raw blobs from all inputs are gathered into the merged out-dir so verify can
    still check artifact integrity.

  merge.py --out-dir merged --sign --home ~/.beacon box-a/package.json box-b/package.json ...
  (verify the result with:  collector.py verify merged/package.json --registry ...)
"""
import argparse
import json
import os
import shutil
import sys

import beaconlib as bl


def load(path):
    with open(path) as f:
        return json.load(f)


def merge(args):
    if len(args.packages) < 2:
        sys.exit("merge needs at least 2 single-box packages")

    pkgs = [load(p) for p in args.packages]
    subjects = {p["subject"]["name"] for p in pkgs}
    if len(subjects) > 1:
        sys.exit("refusing to merge different subjects: %s" % ", ".join(sorted(subjects)))
    subject_name = subjects.pop()

    # Union items, collapsing byte-identical duplicates, keeping per-box variants.
    seen = {}
    boxes = []
    for p, path in zip(pkgs, args.packages):
        # re-verify each input's item hashes before trusting it into the aggregate
        for it in p.get("items", []):
            if bl.hash_item(it) != it.get("item_sha256"):
                sys.exit("input %s has a tampered item (%s); refusing to merge" % (
                    path, it.get("subcriterion")))
            seen.setdefault(it["item_sha256"], it)
        for it in p.get("items", []):
            b = it.get("provenance", {}).get("box", "unknown")
            if b not in boxes:
                boxes.append(b)

    items = list(seen.values())
    items.sort(key=lambda it: (it.get("provenance", {}).get("box", ""), it["subcriterion"]))

    os.makedirs(args.out_dir, exist_ok=True)
    blob_out = os.path.join(args.out_dir, "blobs")
    os.makedirs(blob_out, exist_ok=True)
    for path in args.packages:
        src_blobs = os.path.join(os.path.dirname(os.path.abspath(path)), "blobs")
        if os.path.isdir(src_blobs):
            for fn in os.listdir(src_blobs):
                dst = os.path.join(blob_out, fn)
                if not os.path.exists(dst):
                    shutil.copy2(os.path.join(src_blobs, fn), dst)

    subject = {"name": subject_name, "scope": "multi-box:" + ",".join(sorted(boxes)),
               "collected_utc": bl.utcnow(), "boxes": sorted(boxes)}
    collector = {"name": "beacon-merge", "version": "0.4.0", "platform": "aggregate",
                 "merged_from": len(pkgs), "note": "aggregate of per-box packages; each item keeps provenance.box"}
    core = bl.build_package(subject, collector, items)
    try:
        package = bl.seal_and_sign(core, sign=args.sign, home=args.home)
    except RuntimeError as e:
        sys.exit(str(e))

    out_path = os.path.join(args.out_dir, "package.json")
    with open(out_path, "w") as f:
        f.write(json.dumps(package, indent=2))
    bl.anchor_after_write(out_path, sealed_utc=subject.get("collected_utc"), home=args.home, enabled=not args.no_anchor)

    # per-box coverage summary (facts, not a score)
    by_box = {}
    for it in items:
        by_box.setdefault(it.get("provenance", {}).get("box", "unknown"), []).append(it["subcriterion"])
    print("merged %d packages -> %s" % (len(pkgs), out_path))
    print("  subject: %s  |  boxes: %s" % (subject_name, ", ".join(sorted(boxes))))
    for b in sorted(by_box):
        print("    %-24s %d items: %s" % (b, len(by_box[b]), ", ".join(sorted(set(by_box[b])))))
    print("  package_hash: %s" % package["seal"]["package_hash"])
    print("  per-item provenance.box preserved; duplicates collapsed by item_sha256; NO score.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("packages", nargs="+", help="single-box package.json files to merge")
    ap.add_argument("--out-dir", default="merged")
    ap.add_argument("--sign", action="store_true")
    ap.add_argument("--no-anchor", action="store_true", help="seal only; do not timestamp/anchor the package (state recorded as unanchored)")
    ap.add_argument("--home", default=os.path.expanduser("~/.beacon"))
    a = ap.parse_args()
    merge(a)
