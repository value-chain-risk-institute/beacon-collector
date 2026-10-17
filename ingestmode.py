#!/usr/bin/env python3
"""
ingestmode.py, Beacon Collector adapter: document ingester (policy -> framework clause).

You feed it a policy document and a framework, and it points each framework clause
at the specific excerpt of your policy that addresses it, then seals those pointers
as evidence you own. The Collector proposes; a human confirms; the Collector packages.
It NEVER scores and it NEVER judges whether the policy is good, only where in the
document a clause appears to be addressed, quoted verbatim so a reviewer can check it.

Design: DESIGN-document-ingester-v0.1-Marpet-Viktor.md. This is the v0.1 slice:
- Framework is loaded from a local catalog file (the OSCAL/CSAF fetch from VCRI is
  the next piece; fetch_framework() is the seam for it).
- Matcher is a local, deterministic keyword-overlap baseline (stdlib only, nothing
  leaves the box). The embedding/LLM matcher is the pluggable upgrade: a local
  backend for the open VCRI Collector, a cloud backend only in the CRC build.
- Every mapping is proposed with human.confirmed=false. The confirm UI is the next
  piece; until a human confirms, the package records the proposals as unconfirmed.

Epistemic class: a policy is the subject's own DECLARATION (Stated class,
epistemic="subject_claim", verified_by_collector=false). The Collector verifies the
document's integrity (hash) and that the excerpt is a verbatim span of it; it does
NOT verify that the policy is true or followed.

  ingestmode.py collect --doc policy.md --framework catalogs/cis-8.1-sample.json \
      [--subject NAME] [--floor 0.2] [--no-anchor] [--out-dir out-ingest]
  ingestmode.py verify out-ingest/package.json

Stdlib only. No score.
"""
import argparse
import json
import os
import re
import sys

import adapterkit as ak
import beaconlib as bl
import ingestlib as il

SLOT = "unmapped"  # a policy->clause pointer needs a framework->rubric crosswalk to
                   # reach a scorer slot; until that exists, score.py reports it as a gap.
MODE = "document-mapping"

STOPWORDS = set("""a an the and or of to for in on at by with from as is are be been being this that these those
it its their your our his her they you we i he she them us me my if then than so such not no nor only also any all
each every both either neither which who whom whose what when where why how may might must shall should would could
can will do does did done have has had having into over under between within without about against during before
after above below up down out off per via use used using ensure ensured maintain maintained provide provided""".split())

TOKEN = re.compile(r"[a-z0-9][a-z0-9\-]+")


def tokens(text):
    return [t for t in TOKEN.findall((text or "").lower()) if t not in STOPWORDS and len(t) > 2]


def chunk_document(text):
    """Split into reviewable spans: paragraphs (blank-line separated), each kept
    verbatim with a 1-based paragraph index for the reviewer's location."""
    spans = []
    for i, block in enumerate(re.split(r"\n\s*\n", text)):
        span = block.strip()
        if span:
            spans.append({"index": i + 1, "text": span})
    return spans


def score_span(clause_tokens, span_tokens):
    """Recall of the clause's distinctive vocabulary inside the span, 0..1. Simple,
    deterministic, local. The pluggable matcher (embeddings/LLM) replaces THIS only."""
    if not clause_tokens:
        return 0.0
    hit = sum(1 for t in clause_tokens if t in span_tokens)
    return round(hit / len(clause_tokens), 3)


def match_clause(clause, spans, span_tokens):
    ctoks = set(tokens(clause.get("title", "") + " " + clause.get("text", "")))
    best, best_score = None, 0.0
    for span, stoks in zip(spans, span_tokens):
        s = score_span(ctoks, stoks)
        if s > best_score:
            best, best_score = span, s
    return best, best_score


def collect(args):
    args.doc = args.doc[0] if isinstance(args.doc, list) else args.doc
    if not os.path.exists(args.doc):
        sys.exit("document not found: %s" % args.doc)
    if os.path.splitext(args.doc)[1].lower() not in (".md", ".txt", ".markdown"):
        sys.exit("v0.1 ingests .md/.txt only (PDF/DOCX text-extraction is the next piece)")
    raw = open(args.doc, "rb").read()
    text = raw.decode("utf-8", "replace")
    try:
        fw = il.fetch_framework(args.framework, home=args.home, expected_sha256=args.framework_sha256)
    except il.CatalogError as e:
        sys.exit(str(e))
    fw_hash = fw["catalog_sha256"]

    spans = chunk_document(text)
    if not spans:
        sys.exit("document has no readable text")
    span_tokens = [set(tokens(s["text"])) for s in spans]

    mappings, gaps = [], []
    for clause in fw["clauses"]:
        best, conf = match_clause(clause, spans, span_tokens)
        if best and conf >= args.floor:
            mappings.append({
                "clause_id": clause["id"],
                "clause_title": clause.get("title", ""),
                "excerpt": {"text": best["text"], "location": "paragraph %d" % best["index"]},
                "confidence": conf,
                "human": {"confirmed": False, "by": None, "at": None},
            })
        else:
            gaps.append({"clause_id": clause["id"], "clause_title": clause.get("title", ""),
                         "best_confidence": conf, "note": "no excerpt above the confidence floor; review as a gap"})

    now = bl.utcnow()
    os.makedirs(args.out_dir, exist_ok=True)
    raw_hash = ak.write_blob(args.out_dir, raw)

    obs = {
        "document_mapping": {
            "present": True,
            "framework": {"id": fw["id"], "version": fw.get("version"), "catalog_sha256": fw_hash},
            "source_doc": {"name": os.path.basename(args.doc), "sha256": raw_hash},
            "clauses_total": len(fw["clauses"]),
            "clauses_mapped": len(mappings),
            "clauses_gap": len(gaps),
            "matcher": {"backend": "local-keyword-overlap", "version": "0.1.0", "confidence_floor": args.floor},
            "human_confirmed": False,
            "mappings": mappings,
            "gaps": gaps,
            "note": "AI/automated proposals, verbatim excerpts, UNCONFIRMED. A human must confirm each "
                    "mapping before it is rating-grade. The policy is a subject declaration (Stated class); "
                    "the Collector verifies the excerpt is a verbatim span of the sealed document, not that the "
                    "policy is true or followed.",
        }
    }

    item = ak.make_item(
        SLOT, MODE, "subject_claim", False,
        {"tool": "document-ingester", "kind": "policy:" + fw["id"], "document_name": os.path.basename(args.doc)},
        {"box": args.box or ("doc:" + os.path.basename(args.doc)), "access": "subject-supplied-document"},
        None, obs, raw_hash, now,
        ak.freshness(now, None, "document carries no intrinsic date; age unknown unless the policy states one"),
        ak.unmapped("policy-to-framework-clause proposals; a framework->rubric crosswalk will route confirmed "
                    "mappings to scorer slots", [fw["id"] + ":" + m["clause_id"] for m in mappings]))

    subject = {"name": args.subject or "unknown", "scope": "document:" + fw["id"], "collected_utc": now}
    collector = {"name": "beacon-document-ingester", "version": "0.1.0", "platform": "any"}
    package, out_path = ak.seal_write(args, [item], subject, collector)

    print("ingested %s against %s %s (catalog %s...)" % (
        os.path.basename(args.doc), fw["id"], fw.get("version") or "", fw_hash[:12]))
    print("  %d clauses: %d proposed-mapped, %d gaps (floor %.2f). ALL UNCONFIRMED, pending human review." % (
        len(fw["clauses"]), len(mappings), len(gaps), args.floor))
    for m in mappings:
        print("    %-10s conf %.2f  <- %s" % (m["clause_id"], m["confidence"], m["excerpt"]["location"]))
    ak.summarize([item], package, out_path)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--doc", required=True, help="policy document (.md/.txt)")
    c.add_argument("--framework", required=True, help="framework id from catalogs/index.json, https URL, or file")
    c.add_argument("--framework-sha256", help="pin the catalog bytes; a mismatch is refused")
    c.add_argument("--floor", type=float, default=0.2, help="confidence floor below which a clause is a gap")
    ak.add_common(c, "out-ingest")
    ak.add_verify(sub)
    a = ap.parse_args()
    (collect if a.cmd == "collect" else ak.cmd_verify)(a)
