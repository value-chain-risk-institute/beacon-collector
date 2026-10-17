#!/usr/bin/env python3
"""Tests for the document ingester (ingestmode.py, ingestlib.py, ingestreview.py).

Run: python test_ingest.py      (offline; the only sockets are 127.0.0.1 servers this
suite starts itself, standing in for a catalog host and for the confirm page)

v0.1 claims (kept): Stated class, verbatim excerpts, unconfirmed proposals, package verifies.
v0.2 claims: OSCAL catalogs normalize (nested groups and controls, statement prose with
parameters, withdrawn skipped, objectives and guidance excluded) and every item records
the catalog sha256; fetch from path, URL or index id with hash pinning; .md/.txt/.docx/.pdf
extraction keeps findable locations; BM25 matcher behind a local-only backend interface;
the confirm page is bound to 127.0.0.1, token-gated, escapes document text, refuses
non-verbatim edits, and seals only what a named human confirmed; a crosswalk routes
confirmed mappings to scorer slots as stated evidence, cap 1.
"""
import argparse
import hashlib
import http.server
import json
import os
import tempfile
import threading
import unittest

import beaconlib as bl
import ingestlib as il
import ingestmode as im

HERE = os.path.dirname(os.path.abspath(__file__))
DOC = os.path.join(HERE, "samples", "sample-infosec-policy.md")
FW = os.path.join(HERE, "catalogs", "cis-8.1-sample.json")
POLICY_TEXT = open(DOC, encoding="utf-8").read()
CATS = os.path.join(HERE, "catalogs")
CSF = os.path.join(CATS, "nist-csf-2.0.oscal.json")
R3 = os.path.join(CATS, "nist-sp800-171r3.oscal.json")
FIXT = os.path.join(HERE, "samples", "ingest")
CIS_SHAPE = os.path.join(FIXT, "cis-shape-synthetic.oscal.json")


def file_sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def serve_dir(directory):
    """A 127.0.0.1 stand-in for a catalog host (VCRI, NIST, CIS), for the fetch tests."""
    handler = lambda *a, **k: _QuietHandler(*a, directory=directory, **k)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d/" % srv.server_address[1]


def run_collect(out_dir, floor=0.2):
    args = argparse.Namespace(doc=[DOC], framework=FW, framework_sha256=None, floor=floor, subject="TestCo",
                              matcher="keyword", crosswalk=None,
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


class Catalogs(unittest.TestCase):
    def test_simple_format_still_loads(self):
        fw = il.load_framework(open(FW, "rb").read(), FW)
        self.assertEqual(fw["id"], "cis-8.1-sample")
        self.assertEqual(fw["format"], "simple")
        self.assertEqual(fw["catalog_sha256"], file_sha(FW))
        self.assertEqual([c["id"] for c in fw["clauses"]][:2], ["1.1", "6.3"])

    def test_csf_2_0_subcategories(self):
        fw = il.load_framework(open(CSF, "rb").read(), CSF)
        self.assertEqual(fw["format"], "oscal-catalog")
        self.assertEqual(fw["id"], "nist-csf-2.0", "id comes from the catalog index, bound to the file's hash")
        ids = [c["id"] for c in fw["clauses"]]
        self.assertEqual(len(ids), 106, "CSF 2.0 has 106 subcategories; withdrawn 1.1 entries are skipped")
        self.assertIn("PR.AA-03", ids)
        self.assertNotIn("GV.OC", ids, "categories are parents, not leaf clauses")
        c = [c for c in fw["clauses"] if c["id"] == "PR.AA-03"][0]
        self.assertIn("authenticated", c["text"].lower())
        self.assertEqual(c["oscal_id"], "PR.AA-03")
        self.assertIn("PROTECT", c["group_path"])

    def test_800_171_rev3_requirements(self):
        fw = il.load_framework(open(R3, "rb").read(), R3)
        self.assertEqual(fw["id"], "nist-sp800-171r3")
        self.assertEqual(len(fw["clauses"]), 97, "Rev 3 has 97 requirements once withdrawn entries are skipped")
        c = [c for c in fw["clauses"] if c["id"] == "03.01.01"][0]
        self.assertEqual(c["title"], "Account Management")
        self.assertEqual(c["oscal_id"], "SP_800_171_03.01.01")
        self.assertNotIn("{{", c["text"], "parameter inserts are rendered, not left as template syntax")
        self.assertIn("[Assignment: organization-defined time period]", c["text"])
        self.assertIn("Define the types of system accounts allowed and prohibited.", c["text"])
        self.assertNotIn("This requirement focuses on", c["text"], "guidance prose is not clause text")

    def test_cis_shape_label_ids_and_exclusions(self):
        fw = il.load_framework(open(CIS_SHAPE, "rb").read(), CIS_SHAPE)
        ids = [c["id"] for c in fw["clauses"]]
        self.assertEqual(ids, ["1.1"], "label 'CIS Safeguard 1.1' -> id 1.1; withdrawn 1.2 skipped; parent skipped")
        self.assertNotIn("OBJECTIVE", fw["clauses"][0]["text"])

    def test_rejects_unknown_shape(self):
        with self.assertRaises(il.CatalogError):
            il.load_framework(b'{"profile": {}}', "x.json")

    def test_fetch_local_path_and_pin(self):
        fw = il.fetch_framework(CSF, home=tempfile.mkdtemp())
        self.assertEqual(fw["catalog_sha256"], file_sha(CSF))
        self.assertEqual(fw["source"]["kind"], "path")
        with self.assertRaises(il.CatalogError):
            il.fetch_framework(CSF, home=tempfile.mkdtemp(), expected_sha256="0" * 64)

    def test_fetch_url_records_hash_and_caches(self):
        srv, base = serve_dir(CATS)
        try:
            home = tempfile.mkdtemp()
            fw = il.fetch_framework(base + "nist-sp800-171r3.oscal.json", home=home,
                                    expected_sha256=file_sha(R3), allow_http=True)
            self.assertEqual(fw["catalog_sha256"], file_sha(R3))
            self.assertEqual(fw["source"]["kind"], "url")
            self.assertTrue(os.path.exists(os.path.join(home, "catalogs", "sha256-%s.json" % file_sha(R3))))
            with self.assertRaises(il.CatalogError):
                il.fetch_framework(base + "nist-sp800-171r3.oscal.json", home=home, expected_sha256="f" * 64,
                                   allow_http=True)
            with self.assertRaises(il.CatalogError):
                il.fetch_framework(base + "nist-sp800-171r3.oscal.json", home=home)  # plain http refused by default
        finally:
            srv.shutdown()

    def test_fetch_by_index_id(self):
        fw = il.fetch_framework("nist-csf-2.0", home=tempfile.mkdtemp())
        self.assertEqual(fw["id"], "nist-csf-2.0")
        self.assertEqual(fw["source"]["kind"], "index")
        index = json.load(open(os.path.join(CATS, "index.json")))
        cis = index["frameworks"]["cis-8.1"]
        self.assertTrue(cis["url"].startswith("https://bitbucket.org/cis-it-workspace/"))
        self.assertNotIn("path", cis, "CIS terms of use do not allow redistribution; fetched at run time, never vendored")
        self.assertEqual(len(cis["sha256"]), 64)

    def test_every_item_records_catalog_hash(self):
        tmp = tempfile.mkdtemp()
        args = argparse.Namespace(doc=[DOC], framework=CSF, framework_sha256=None, floor=0.2, subject="TestCo",
                                  box=None, sign=False, no_anchor=True, matcher="bm25", crosswalk=None,
                                  home=os.path.join(tmp, ".beacon"), out_dir=tmp)
        im.collect(args)
        pkg = json.load(open(os.path.join(tmp, "package.json")))
        for it in pkg["items"]:
            fwk = [v for v in it["observation"].values() if isinstance(v, dict)][0]["framework"]
            self.assertEqual(fwk["catalog_sha256"], file_sha(CSF))


if __name__ == "__main__":
    unittest.main(verbosity=2)
