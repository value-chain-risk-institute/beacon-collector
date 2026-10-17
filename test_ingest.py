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


W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def make_docx(path, paragraphs, table_rows=None, doctype=False):
    """A minimal real .docx (zip + WordprocessingML), written by hand for the tests.
    paragraphs: [(style_id or None, text)]; style ids map to names in styles.xml the
    way Word writes them (Heading1 -> 'heading 1')."""
    from xml.sax.saxutils import escape

    def para(style, text):
        ppr = '<w:pPr><w:pStyle w:val="%s"/></w:pPr>' % style if style else ""
        runs = "".join('<w:r><w:t xml:space="preserve">%s</w:t></w:r>' % escape(t) for t in text.split("|"))
        return "<w:p>%s%s</w:p>" % (ppr, runs)

    body = "".join(para(s, t) for s, t in paragraphs)
    if table_rows:
        body += "<w:tbl>" + "".join("<w:tr>" + "".join("<w:tc>%s</w:tc>" % para(None, c) for c in row) + "</w:tr>"
                                   for row in table_rows) + "</w:tbl>"
    dt = '<!DOCTYPE x [<!ENTITY a "aaaa">]>' if doctype else ""
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>%s<w:document xmlns:w="%s"><w:body>%s'
           '</w:body></w:document>' % (dt, W_NS, body))
    styles = ('<?xml version="1.0" encoding="UTF-8"?><w:styles xmlns:w="%s">'
              '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/></w:style>'
              '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/></w:style>'
              '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/></w:style>'
              '<w:style w:type="paragraph" w:styleId="Normal"><w:name w:val="Normal"/></w:style></w:styles>' % W_NS)
    ctypes = ('<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/'
              'content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/'
              'document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.'
              'main+xml"/></Types>')
    import zipfile
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ctypes)
        z.writestr("word/document.xml", doc)
        z.writestr("word/styles.xml", styles)
    return path


def make_pdf(path, pages):
    """A minimal real PDF (Helvetica text, one content stream per page), by hand.
    pages: [[line, ...], ...]; an empty line leaves a blank line."""
    objs = ["<< /Type /Catalog /Pages 2 0 R >>", None, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    kids = []
    for lines in pages:
        ops = ["BT /F1 11 Tf 14 TL 72 740 Td"]
        for ln in lines:
            ops.append("(%s) Tj T*" % ln.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)"))
        ops.append("ET")
        stream = "\n".join(ops).encode("latin-1")
        objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        objs.append(None)
        kids.append(len(objs))
        objs[-1] = ("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> "
                    "/Contents %d 0 R >>" % (len(objs) - 1))
    objs[1] = "<< /Type /Pages /Kids [%s] /Count %d >>" % (" ".join("%d 0 R" % k for k in kids), len(kids))
    out = bytearray(b"%PDF-1.4\n")
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        body = o if isinstance(o, bytes) else o.encode("latin-1")
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offs:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    with open(path, "wb") as f:
        f.write(bytes(out))
    return path


class Documents(unittest.TestCase):
    def assert_offsets(self, doc):
        for ch in doc["chunks"]:
            self.assertEqual(doc["text"][ch["start"]:ch["end"]], ch["text"], "chunk offsets must address the text")

    def test_markdown_sections_and_paragraphs(self):
        doc = il.extract_document(DOC)
        self.assertEqual(doc["kind"], "markdown")
        self.assertEqual(doc["sha256"], file_sha(DOC))
        self.assert_offsets(doc)
        self.assertFalse(any(ch["text"].startswith("#") for ch in doc["chunks"]), "headings label, they are not spans")
        bk = [ch for ch in doc["chunks"] if "Automated backups" in ch["text"]][0]
        self.assertEqual(bk["section"], "Backups")
        self.assertIsNone(bk["page"])
        self.assertIn("Backups", il.location_text(doc, bk))
        for ch in doc["chunks"]:
            self.assertIn(ch["text"], POLICY_TEXT)

    def test_text_file(self):
        p = os.path.join(tempfile.mkdtemp(), "policy.txt")
        open(p, "w").write("BACKUPS\n\nBackups run nightly and copies are kept offline.\n\nPasswords are never shared.\n")
        doc = il.extract_document(p)
        self.assertEqual(doc["kind"], "text")
        self.assert_offsets(doc)
        self.assertEqual([c["paragraph"] for c in doc["chunks"]], [1, 2])
        self.assertEqual(doc["chunks"][0]["section"], "BACKUPS")

    def test_docx_headings_paragraphs_tables(self):
        p = make_docx(os.path.join(tempfile.mkdtemp(), "Policy.docx"), [
            ("Title", "Security Policy"), ("Heading1", "Access"), (None, "Remote access |requires MFA."),
            (None, ""), ("Heading2", "Backups"), (None, "Backups run nightly.")],
            table_rows=[["Owner", "IT team reviews backups monthly."]])
        doc = il.extract_document(p)
        self.assertEqual(doc["kind"], "docx")
        self.assert_offsets(doc)
        texts = [c["text"] for c in doc["chunks"]]
        self.assertIn("Remote access requires MFA.", texts, "runs join verbatim")
        self.assertNotIn("Access", texts, "a heading is a section label, not a span")
        mfa = [c for c in doc["chunks"] if "MFA" in c["text"]][0]
        self.assertEqual(mfa["section"], "Access")
        self.assertEqual(mfa["paragraph"], 3, "non-empty body paragraphs, headings included, 1-based")
        tbl = [c for c in doc["chunks"] if "monthly" in c["text"]][0]
        self.assertEqual(tbl["section"], "Backups")

    def test_docx_with_dtd_refused(self):
        p = make_docx(os.path.join(tempfile.mkdtemp(), "evil.docx"), [(None, "x")], doctype=True)
        with self.assertRaises(il.DocumentError):
            il.extract_document(p)

    def test_not_a_docx(self):
        p = os.path.join(tempfile.mkdtemp(), "fake.docx")
        open(p, "wb").write(b"not a zip")
        with self.assertRaises(il.DocumentError):
            il.extract_document(p)

    def test_unsupported_extension(self):
        p = os.path.join(tempfile.mkdtemp(), "x.rtf")
        open(p, "w").write("{\\rtf1}")
        with self.assertRaises(il.DocumentError):
            il.extract_document(p)

    def test_pdf_pages(self):
        p = make_pdf(os.path.join(tempfile.mkdtemp(), "policy.pdf"), [
            ["Information Security Policy", "", "Asset inventory is reviewed quarterly."],
            ["Backups", "", "Automated backups run nightly and copies are kept offline."]])
        if not il.have_pypdf():
            with self.assertRaises(il.DocumentError) as cm:
                il.extract_document(p)
            self.assertIn("pypdf", str(cm.exception))
            self.skipTest("pypdf not installed; the clear-message path was checked instead")
        doc = il.extract_document(p)
        self.assertEqual(doc["kind"], "pdf")
        self.assert_offsets(doc)
        bk = [c for c in doc["chunks"] if "nightly" in c["text"]][0]
        self.assertEqual(bk["page"], 2)
        self.assertIn("p.2", il.location_text(doc, bk))

    def test_pdf_without_pypdf_is_a_clear_message(self):
        p = make_pdf(os.path.join(tempfile.mkdtemp(), "policy.pdf"), [["One line."]])
        real = il.have_pypdf
        il.have_pypdf = lambda: False
        try:
            with self.assertRaises(il.DocumentError) as cm:
                il.extract_document(p)
            self.assertIn("pip install", str(cm.exception))
        finally:
            il.have_pypdf = real


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
