#!/usr/bin/env python3
"""
point.py, Beacon Collector: sealed span pointers from a document to a framework requirement.

The vendor says "I think these lines answer this requirement." That sentence is worth sealing
exactly as it is: a CLAIM (Stated class), bound to a specific document hash and line range, with
the quoted span, by a named person, at a time. It is not an evaluation. It is the thing a paid
examination later confirms or refuses, and it is what fills the "no automated source" rows of a
framework coverage report honestly.

Two provenance modes:
  --by "Name, role"      a person points: epistemic subject_claim (Stated). Enters coverage.
  --model NAME           a model suggested the span: epistemic ai_inference. Listed as
                         "suggested, unconfirmed"; never enters coverage or arithmetic until a
                         person re-points it with --by (the Antares rule: AI is a lead, not evidence).

  point.py --doc policy.pdf --framework nist-sp800-171r2 --by "J. Smith, CISO" \
           --claim "3.2.1|40-52|Managers and system administrators complete..." \
           --claim "3.2.2|60-71|All personnel complete role-based training..." \
           --out-dir pointers
  merge.py --out-dir merged main/package.json pointers/package.json   # one sealed bundle
"""
import argparse, hashlib, json, os, shutil, sys
import beaconlib as bl

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--doc", required=True, help="the document the pointers refer to (hashed and copied into blobs/)")
    ap.add_argument("--framework", required=True, help="framework key, e.g. nist-sp800-171r2")
    ap.add_argument("--claim", action="append", required=True, help='"REQ_ID|LINES|quoted span" (repeatable)')
    ap.add_argument("--by", help='person who points, "Name, role" (Stated class)')
    ap.add_argument("--model", help="model that suggested the span (ai_inference; never counts until a person confirms)")
    ap.add_argument("--subject", default="", help='subject name (must match the package it will be merged with)')
    ap.add_argument("--subject-json", help="path to a JSON file with the subject block (preferred, exact match for merge)")
    ap.add_argument("--out-dir", default="pointers")
    ap.add_argument("--sign", action="store_true")
    ap.add_argument("--home", default=os.path.expanduser("~/.beacon"))
    a = ap.parse_args()
    if not a.by and not a.model:
        sys.exit("one of --by (a person) or --model (a suggestion) is required")
    raw = open(a.doc, "rb").read()
    doc_hash = hashlib.sha256(raw).hexdigest()
    os.makedirs(os.path.join(a.out_dir, "blobs"), exist_ok=True)
    shutil.copy2(a.doc, os.path.join(a.out_dir, "blobs", "sha256-" + doc_hash))
    now = bl.utcnow()
    items = []
    for c in a.claim:
        try:
            req, lines, quote = c.split("|", 2)
        except ValueError:
            sys.exit("bad --claim (want REQ_ID|LINES|quote): " + c)
        epistemic = "subject_claim" if a.by else "ai_inference"
        items.append({
            "subcriterion": "%s:%s" % (a.framework, req.strip()),
            "mode": "document",
            "epistemic": epistemic,
            "tool": "point.py",
            "provenance": {"document_sha256": doc_hash, "document_name": os.path.basename(a.doc),
                           "pointed_by": a.by, "suggested_by_model": a.model},
            "observation": {"pointer": {"present": True, "requirement": req.strip(), "lines": lines.strip(),
                                        "quote": quote.strip(), "document_sha256": doc_hash}},
            "verified_by_collector": False,
            "context": [],
            "completeness": {"expected": ["pointer"], "obtained": ["pointer"], "fraction": 1.0,
                             "note": "a pointer proves the document says this at these lines; it does not prove the practice"},
            "freshness": {"collected_utc": now, "note": "the document's own date governs age"},
            "artifact_ref": "blob/sha256-" + doc_hash,
            "collected_utc": now,
        })
    subject = json.load(open(a.subject_json)) if a.subject_json else {"name": a.subject}
    collector = {"name": "beacon-collector/point", "version": "0.1",
                 "note": "span pointers are claims about a sealed document, Stated class; ai_inference pointers never count until a person confirms"}
    core = bl.build_package(subject, collector, items)
    pkg = bl.seal_and_sign(core, sign=a.sign, home=a.home)
    out = os.path.join(a.out_dir, "package.json")
    json.dump(pkg, open(out, "w"), indent=1)
    print("sealed %d pointer(s) to %s -> %s" % (len(items), os.path.basename(a.doc), out))

if __name__ == "__main__":
    main()
