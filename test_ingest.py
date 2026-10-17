#!/usr/bin/env python3
"""Tests for ingestmode.py (document ingester v0.1). Stdlib only."""
import argparse
import os
import tempfile
import unittest

import beaconlib as bl
import ingestmode as im

HERE = os.path.dirname(os.path.abspath(__file__))
DOC = os.path.join(HERE, "samples", "sample-infosec-policy.md")
FW = os.path.join(HERE, "catalogs", "cis-8.1-sample.json")
POLICY_TEXT = open(DOC, encoding="utf-8").read()


def run_collect(out_dir, floor=0.2):
    args = argparse.Namespace(doc=DOC, framework=FW, floor=floor, subject="TestCo",
                              box=None, sign=False, no_anchor=True,
                              home=os.path.join(out_dir, ".beacon"), out_dir=out_dir)
    im.collect(args)
    import json
    return json.load(open(os.path.join(out_dir, "package.json")))


class Matcher(unittest.TestCase):
    def test_overlap_recall(self):
        ct = set(im.tokens("Require multi-factor authentication MFA for remote access"))
        hi = set(im.tokens("All remote access requires multi-factor authentication"))
        lo = set(im.tokens("Employees must not share passwords"))
        self.assertGreater(im.score_span(ct, hi), im.score_span(ct, lo))

    def test_chunk_keeps_verbatim(self):
        spans = im.chunk_document("Para one.\n\nPara two here.")
        self.assertEqual(len(spans), 2)
        self.assertEqual(spans[1]["text"], "Para two here.")


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.pkg = run_collect(self.tmp)
        self.item = self.pkg["items"][0]
        self.dm = self.item["observation"]["document_mapping"]

    def test_item_shape_is_stated_and_unverified(self):
        self.assertEqual(self.item["mode"], "document-mapping")
        self.assertEqual(self.item["epistemic"], "subject_claim")
        self.assertFalse(self.item["verified_by_collector"])
        self.assertEqual(self.item["subcriterion"], "unmapped")

    def test_covered_clauses_mapped(self):
        mapped = {m["clause_id"] for m in self.dm["mappings"]}
        for cid in ("1.1", "6.3", "8.2", "11.2"):
            self.assertIn(cid, mapped, "%s should map to the sample policy" % cid)

    def test_uncovered_clause_is_a_gap(self):
        gaps = {g["clause_id"] for g in self.dm["gaps"]}
        self.assertIn("7.1", gaps, "vulnerability management is not in the sample policy; expected a gap")

    def test_excerpts_are_verbatim(self):
        for m in self.dm["mappings"]:
            self.assertIn(m["excerpt"]["text"], POLICY_TEXT,
                          "excerpt for %s must be a verbatim span of the document" % m["clause_id"])

    def test_all_proposals_unconfirmed(self):
        self.assertFalse(self.dm["human_confirmed"])
        for m in self.dm["mappings"]:
            self.assertFalse(m["human"]["confirmed"])

    def test_package_verifies(self):
        ok = bl.verify_package(self.pkg, blob_dir=os.path.join(self.tmp, "blobs"), registry=None)
        self.assertTrue(ok, "sealed ingester package must verify")


if __name__ == "__main__":
    unittest.main(verbosity=2)
