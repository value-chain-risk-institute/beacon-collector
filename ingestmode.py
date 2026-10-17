#!/usr/bin/env python3
"""
ingestmode.py, Beacon Collector adapter: document ingester (policy -> framework clause).

You feed it one or more policy documents and a framework, and it points each
framework clause at the specific excerpt of your policy that appears to address it,
a human confirms or corrects each pointer on a local page, and the Collector seals
the confirmed pointers as evidence you own. The Collector proposes; a human
confirms; the Collector packages. It NEVER scores and it NEVER judges whether the
policy is good, only where in the document a clause appears to be addressed, quoted
verbatim with a location so a reviewer can check it.

Design: DESIGN-document-ingester-v0.1-Marpet-Viktor.md (decisions 2026-10-09).
v0.2 (2026-10-16):
- Frameworks are data: an OSCAL catalog or the simple {id, version, clauses} file,
  picked by index id (catalogs/index.json), https URL or path, pinned by sha256,
  and the catalog hash is recorded in every item (ingestlib.fetch_framework).
- Documents: .md, .txt, .docx (stdlib) and .pdf (optional pypdf). Every excerpt is a
  verbatim span with doc, page or section, and paragraph index.
- Matcher: local BM25 (stdlib) behind a backend interface; clauses below the
  confidence floor become gaps. No network backend exists in the open build, and
  one that declares network access is refused.
- Review: `review` serves the confirm page on 127.0.0.1 (ingestreview.py). Only
  mappings a named reviewer confirmed are sealed as confirmed; "not covered"
  becomes a recorded gap. `collect` seals the proposals UNCONFIRMED, as v0.1 did.
- Crosswalk (optional, --crosswalk): framework clause -> VCRI rubric subcriterion.
  Each CONFIRMED mapping on a crosswalked clause is emitted again on that rubric's
  evidence-map slot as stated-class evidence (score.py caps it at level 1). A
  target with no slot in the evidence map is emitted as "unmapped", a reported gap.

Epistemic class: a policy is the subject's own DECLARATION (Stated class,
epistemic="subject_claim", verified_by_collector=false). The Collector verifies the
document's integrity (hash) and that the excerpt is a verbatim span of it; it does
NOT verify that the policy is true or followed. Human confirmation does not raise
the class; it makes the pointer checkable (who confirmed which sentence, when).

  ingestmode.py review  --doc policy.docx [--doc standard.md] --framework cis-8.1 \\
      [--crosswalk crosswalks/DRAFT-cis-8.1-to-vcri-rubrics.json] [--floor 0.2] \\
      [--matcher bm25] [--no-browser] [--subject NAME] [--no-anchor] [--out-dir out-ingest]
  ingestmode.py collect --doc policy.md --framework nist-sp800-171r3 [same options]
  ingestmode.py frameworks          # list the catalog index
  ingestmode.py verify out-ingest/package.json

--framework takes an id from catalogs/index.json (nist-csf-2.0, nist-sp800-171r3,
cis-8.1), an https URL to an OSCAL catalog JSON, or a local file.

Stdlib only (pypdf optional, for .pdf). No score.
"""
import argparse
import json
import os
import sys

import adapterkit as ak
import beaconlib as bl
import ingestlib as il

HERE = os.path.dirname(os.path.abspath(__file__))
SLOT = "unmapped"  # the per-document mapping record has no single rubric home; the
                   # crosswalk items below carry the confirmed pointers to slots
MODE = "document-mapping"
VERSION = "0.2.0"
EVIDENCE_MAP = os.path.join(HERE, "scorer-evidence-map-v0.json")

# v0.1 names, kept for callers and tests
tokens = il.tokens
STOPWORDS = il.STOPWORDS


def chunk_document(text):
    return [{"index": c["paragraph"], "text": c["text"]} for c in il._chunks_from_text(text, markdown=True)]


def score_span(clause_tokens, span_tokens):
    if not clause_tokens:
        return 0.0
    return round(sum(1 for t in clause_tokens if t in span_tokens) / len(clause_tokens), 3)


# ---------------------------------------------------------------- session

def open_session(args):
    """Load the framework and documents and run the matcher. Everything the review
    page and the sealer need, in one dict. Nothing here touches the network except
    fetch_framework (a public catalog)."""
    try:
        fw = il.fetch_framework(args.framework, home=args.home, expected_sha256=getattr(args, "framework_sha256", None))
    except il.CatalogError as e:
        sys.exit(str(e))
    docs = []
    for path in args.doc:
        try:
            docs.append(il.extract_document(path))
        except il.DocumentError as e:
            sys.exit(str(e))
    names = [d["name"] for d in docs]
    if len(set(names)) != len(names):
        sys.exit("two documents share a file name; rename one so locations are unambiguous")
    try:
        backend = il.get_backend(getattr(args, "matcher", None) or "bm25")
    except il.MatcherError as e:
        sys.exit(str(e))
    rows = il.propose(fw, docs, backend, floor=args.floor)
    crosswalk = None
    if getattr(args, "crosswalk", None):
        try:
            crosswalk = il.load_crosswalk(args.crosswalk, fw)
        except il.CatalogError as e:
            sys.exit(str(e))
    return {"fw": fw, "docs": docs, "rows": rows, "floor": args.floor, "crosswalk": crosswalk,
            "matcher": {"backend": backend.name, "version": backend.version, "network": backend.network,
                        "confidence_floor": args.floor, "run_at": bl.utcnow()},
            "decisions": {}, "reviewer": None}


def framework_header(fw):
    return {"id": fw["id"], "version": fw.get("version"), "title": fw.get("title"), "format": fw.get("format"),
            "catalog_sha256": fw["catalog_sha256"], "source": fw.get("source")}


def _mapping(sess, row, excerpt, human, proposed=None):
    fw, doc = sess["fw"], sess["docs"][excerpt["doc"]]
    m = {"type": "document-mapping",
         "framework": {"id": fw["id"], "version": fw.get("version"), "catalog_sha256": fw["catalog_sha256"]},
         "clause_id": row["clause_id"], "oscal_id": row.get("oscal_id"), "clause_title": row["clause_title"],
         "source_doc": {"name": doc["name"], "sha256": doc["sha256"]},
         "excerpt": {"text": excerpt["text"], "location": excerpt["location"],
                     "location_text": excerpt["location_text"]},
         "confidence": row["confidence"] if proposed is None or proposed.get("text") else None,
         "mapper": {"model": sess["matcher"]["backend"], "version": sess["matcher"]["version"],
                    "run_at": sess["matcher"]["run_at"]},
         "human": human}
    if proposed is not None:
        m["proposed_excerpt"] = proposed
    return m


def resolve(sess):
    """Apply the reviewer's decisions to the proposals: (mappings, gaps)."""
    mappings, gaps = [], []
    rev = sess.get("reviewer")
    for row in sess["rows"]:
        d = sess["decisions"].get(row["clause_id"])
        if d and d["action"] == "confirm" and row.get("excerpt"):
            mappings.append(_mapping(sess, row, row["excerpt"],
                                     {"confirmed": True, "by": rev, "at": d["at"], "decision": "confirmed"}))
        elif d and d["action"] == "edit":
            proposed = ({"text": row["excerpt"]["text"], "location_text": row["excerpt"]["location_text"]}
                        if row.get("excerpt") and row["status"] == "proposed" else {"text": None,
                                                                                    "note": "no proposal above the floor; span supplied by the reviewer"})
            mappings.append(_mapping(sess, row, d["excerpt"],
                                     {"confirmed": True, "by": rev, "at": d["at"], "decision": "edited"}, proposed))
        elif d and d["action"] == "not_covered":
            gaps.append({"clause_id": row["clause_id"], "clause_title": row["clause_title"],
                         "best_confidence": row["confidence"], "reason": "reviewer_marked_not_covered",
                         "by": rev, "at": d["at"]})
        elif row["status"] == "proposed":
            mappings.append(_mapping(sess, row, row["excerpt"],
                                     {"confirmed": False, "by": None, "at": None, "decision": None}))
        else:
            gaps.append({"clause_id": row["clause_id"], "clause_title": row["clause_title"],
                         "best_confidence": row["confidence"], "reason": "below_confidence_floor",
                         "note": "no excerpt above the confidence floor; review as a gap"})
    return mappings, gaps


def build_items(sess, out_dir, now):
    fw, docs = sess["fw"], sess["docs"]
    fwh = framework_header(fw)
    mappings, gaps = resolve(sess)
    confirmed = [m for m in mappings if m["human"]["confirmed"]]
    reviewed = sess.get("reviewer") is not None
    items = []
    doc_hashes = [ak.write_blob(out_dir, d["raw"]) for d in docs]
    fresh = ak.freshness(now, None, "document carries no intrinsic date; age unknown unless the policy states one")
    for i, doc in enumerate(docs):
        mine = [m for m in mappings if m["source_doc"]["sha256"] == doc["sha256"]]
        obs = {"present": True, "framework": fwh,
               "source_doc": {"name": doc["name"], "sha256": doc["sha256"], "kind": doc["kind"],
                              "extraction": doc["extraction"]},
               "clauses_total": len(fw["clauses"]),
               "mappings_confirmed": sum(1 for m in mine if m["human"]["confirmed"]),
               "mappings_unconfirmed": sum(1 for m in mine if not m["human"]["confirmed"]),
               "matcher": sess["matcher"], "human_confirmed": any(m["human"]["confirmed"] for m in mine),
               "reviewer": sess.get("reviewer"), "mappings": mine,
               "note": "Policy-to-clause pointers with verbatim excerpts. human.confirmed=true means a named "
                       "reviewer confirmed (or corrected) the span; false means an automated proposal nobody "
                       "confirmed. The policy is a subject declaration (Stated class); the Collector verifies the "
                       "excerpt is a verbatim span of the sealed document, not that the policy is true or followed."}
        if len(docs) == 1:
            # one document: the gaps live beside its mappings, as in v0.1
            obs["gaps"] = gaps
            obs["clauses_gap"] = len(gaps)
            obs["clauses_mapped"] = len(mine)
        items.append(ak.make_item(
            SLOT, MODE, "subject_claim", False,
            {"tool": "document-ingester", "kind": "policy:" + fw["id"], "document_name": doc["name"]},
            {"box": sess.get("box") or ("doc:" + doc["name"]), "access": "subject-supplied-document"},
            "document_mapping", obs, doc_hashes[i], now, fresh,
            ak.unmapped("policy-to-framework-clause pointers; a framework->rubric crosswalk routes confirmed "
                        "mappings to scorer slots", sorted({fw["id"] + ":" + m["clause_id"] for m in mine}))))

    # The review record: what was proposed, what the human decided, who and when.
    # It is the raw artifact behind the summary item and its bytes are sealed as a blob.
    record = {"schema": "vcri.beacon.document-review/v0", "framework": fwh,
              "documents": [{"name": d["name"], "sha256": d["sha256"]} for d in docs],
              "matcher": sess["matcher"], "reviewer": sess.get("reviewer"), "sealed_utc": now,
              "proposals": [{k: v for k, v in r.items() if k != "clause_text"} for r in sess["rows"]],
              "decisions": {k: {kk: vv for kk, vv in v.items()} for k, v in sorted(sess["decisions"].items())}}
    rec_hash = ak.write_blob(out_dir, json.dumps(record, indent=1, sort_keys=True).encode())
    summary = {"present": True, "framework": fwh,
               "documents": record["documents"], "clauses_total": len(fw["clauses"]),
               "clauses_confirmed": len({m["clause_id"] for m in confirmed}),
               "clauses_unconfirmed": len({m["clause_id"] for m in mappings if not m["human"]["confirmed"]}),
               "clauses_gap": len(gaps), "gaps": gaps, "reviewed": reviewed, "reviewer": sess.get("reviewer"),
               "matcher": sess["matcher"],
               "crosswalk": None if not sess.get("crosswalk") else {k: sess["crosswalk"][k] for k in
                                                                     ("id", "version", "status", "sha256")},
               "note": "Gaps are clauses with no confirmed or proposed excerpt: below the confidence floor, or "
                       "marked not covered by the reviewer. A gap is evidence of absence in THESE documents, "
                       "not a finding about the organization."}
    items.append(ak.make_item(
        SLOT, MODE, "subject_claim", False,
        {"tool": "document-ingester", "kind": "review-record:" + fw["id"]},
        {"box": sess.get("box") or "document-review", "access": "local-confirm-page" if reviewed else "none"},
        "document_mapping_summary", summary, rec_hash, now,
        ak.freshness(now, None, "review record written at seal time"),
        ak.unmapped("coverage summary and gaps of a policy-to-framework mapping", [])))

    if sess.get("crosswalk") and confirmed:
        items.extend(crosswalk_items(sess, confirmed, doc_hashes, now, fresh))
    return items, mappings, gaps


def load_emap(path=EVIDENCE_MAP):
    return json.load(open(path))


def crosswalk_items(sess, confirmed, doc_hashes, now, fresh, emap=None):
    """One stated-class item per (rubric target, document) for confirmed mappings on
    crosswalked clauses. Unconfirmed proposals never reach a slot."""
    emap = emap or load_emap()
    cw, fw = sess["crosswalk"], sess["fw"]
    by_target = {}
    for m in confirmed:
        for tgt in cw["entries"].get(m["clause_id"], {}).get("targets", []):
            d = [i for i, doc in enumerate(sess["docs"]) if doc["sha256"] == m["source_doc"]["sha256"]][0]
            by_target.setdefault((tgt["rubric"], tgt["key"], d), []).append(m)
    out = []
    for (rubric, key, d), ms in sorted(by_target.items()):
        slot = il.resolve_slot(emap, rubric, key)
        stated = {"present": True, "kind": "policy-excerpt", "human_confirmed": True,
                  "framework": framework_header(fw),
                  "crosswalk": {"id": cw["id"], "version": cw["version"], "status": cw["status"],
                                "sha256": cw["sha256"], "target": {"rubric": rubric, "key": key}},
                  "clauses": [{"clause_id": m["clause_id"], "clause_title": m["clause_title"],
                               "excerpt": m["excerpt"], "confirmed_by": m["human"]["by"],
                               "confirmed_at": m["human"]["at"], "decision": m["human"]["decision"]} for m in ms],
                  "note": "the subject's policy states this (verbatim, human-confirmed pointer). Stated class: "
                          "a declaration, not an observation; the scorer caps it at level 1."}
        via = "crosswalk %s (%s): %s %s -> %s/%s" % (cw["id"], cw["status"], fw["id"],
                                                    ",".join(m["clause_id"] for m in ms), rubric, key)
        mapping = ak.mapped(via) if slot else ak.unmapped(
            "crosswalk target %s/%s has no slot in the scorer evidence map" % (rubric, key), ["%s:%s" % (rubric, key)])
        out.append(ak.make_item(
            slot or SLOT, MODE, "subject_claim", False,
            {"tool": "document-ingester", "kind": "policy-excerpt:" + fw["id"],
             "document_name": sess["docs"][d]["name"]},
            {"box": sess.get("box") or ("doc:" + sess["docs"][d]["name"]), "access": "subject-supplied-document"},
            "stated", stated, doc_hashes[d], now, fresh, mapping))
    return out


def seal_session(sess, args):
    now = bl.utcnow()
    os.makedirs(args.out_dir, exist_ok=True)
    sess["box"] = getattr(args, "box", None)
    items, mappings, gaps = build_items(sess, args.out_dir, now)
    subject = {"name": args.subject or "unknown", "scope": "document:" + sess["fw"]["id"], "collected_utc": now}
    collector = {"name": "beacon-document-ingester", "version": VERSION, "platform": "any"}
    package, out_path = ak.seal_write(args, items, subject, collector)
    return package, out_path, mappings, gaps


def print_rows(sess):
    fw = sess["fw"]
    n_prop = sum(1 for r in sess["rows"] if r["status"] == "proposed")
    print("ingested %s against %s %s (catalog %s...)" % (
        ", ".join(d["name"] for d in sess["docs"]), fw["id"], fw.get("version") or "", fw["catalog_sha256"][:12]))
    print("  %d clauses: %d proposed, %d below the floor (%.2f, matcher %s)." % (
        len(fw["clauses"]), n_prop, len(fw["clauses"]) - n_prop, sess["floor"], sess["matcher"]["backend"]))
    for r in sess["rows"]:
        if r["status"] == "proposed":
            print("    %-12s conf %.2f  <- %s" % (r["clause_id"], r["confidence"], r["excerpt"]["location_text"]))


def collect(args):
    """Propose and seal WITHOUT review: every mapping is sealed human.confirmed=false."""
    if not isinstance(args.doc, list):
        args.doc = [args.doc]
    sess = open_session(args)
    print_rows(sess)
    package, out_path, mappings, gaps = seal_session(sess, args)
    print("  ALL UNCONFIRMED, pending human review (use `review` for the confirm page).")
    ak.summarize(package["items"], package, out_path)


def review(args):
    import ingestreview
    if not isinstance(args.doc, list):
        args.doc = [args.doc]
    sess = open_session(args)
    print_rows(sess)
    ingestreview.serve(sess, lambda s: seal_session(s, args), open_browser=not args.no_browser)


def frameworks(args):
    for fid, e in sorted(il.load_index().items()):
        print("%-18s %-8s %s" % (fid, "vendored" if e.get("path") else "fetched", e.get("title", "")))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Beacon Collector document ingester (policy -> framework clause)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("collect", "review"):
        c = sub.add_parser(name)
        c.add_argument("--doc", required=True, action="append", help="policy document (.md/.txt/.docx/.pdf); repeatable")
        c.add_argument("--framework", required=True, help="framework id from catalogs/index.json, https URL, or file")
        c.add_argument("--framework-sha256", help="pin the catalog bytes; a mismatch is refused")
        c.add_argument("--floor", type=float, default=0.2, help="confidence floor below which a clause is a gap")
        c.add_argument("--matcher", default="bm25", choices=sorted(il.BACKENDS), help="local matcher backend")
        c.add_argument("--crosswalk", help="optional framework->VCRI rubric crosswalk (DRAFT examples in crosswalks/)")
        if name == "review":
            c.add_argument("--no-browser", action="store_true", help="print the URL; do not open a browser")
        ak.add_common(c, "out-ingest")
    sub.add_parser("frameworks")
    ak.add_verify(sub)
    a = ap.parse_args(argv)
    {"collect": collect, "review": review, "frameworks": frameworks, "verify": ak.cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    main()
