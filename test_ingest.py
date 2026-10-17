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
import ingestreview as ir

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


def run_collect(out_dir, floor=0.2, matcher="keyword", docs=None, framework=FW):
    args = argparse.Namespace(doc=docs or [DOC], framework=framework, framework_sha256=None, floor=floor,
                              subject="TestCo", matcher=matcher, crosswalk=None,
                              box=None, sign=False, no_anchor=True,
                              home=os.path.join(out_dir, ".beacon"), out_dir=out_dir)
    im.collect(args)
    import json
    return json.load(open(os.path.join(out_dir, "package.json")))


class EndToEndBM25(unittest.TestCase):
    def test_v01_expectations_hold_on_bm25(self):
        tmp = tempfile.mkdtemp()
        pkg = run_collect(tmp, matcher="bm25")
        dm = pkg["items"][0]["observation"]["document_mapping"]
        self.assertEqual(dm["matcher"]["backend"], "local-bm25")
        self.assertEqual({m["clause_id"] for m in dm["mappings"]}, {"1.1", "6.3", "8.2", "11.2"})
        self.assertEqual([g["clause_id"] for g in dm["gaps"]], ["7.1"])
        self.assertTrue(bl.verify_package(pkg, blob_dir=os.path.join(tmp, "blobs"), registry=None))

    def test_multi_document_package(self):
        tmp = tempfile.mkdtemp()
        dx = make_docx(os.path.join(tmp, "Backup-Standard.docx"), [
            ("Heading1", "Vulnerability management"),
            (None, "A documented vulnerability management process identifies, assesses and remediates "
                   "vulnerabilities on enterprise assets, reviewed every quarter.")])
        pkg = run_collect(os.path.join(tmp, "out"), matcher="bm25", docs=[DOC, dx])
        modes = [list(it["observation"])[0] for it in pkg["items"]]
        self.assertEqual(modes, ["document_mapping", "document_mapping", "document_mapping_summary"])
        self.assertEqual(pkg["items"][1]["source"]["raw_sha256"], file_sha(dx), "each document is its own sealed blob")
        summary = pkg["items"][2]["observation"]["document_mapping_summary"]
        self.assertEqual(summary["clauses_gap"], 0, "7.1 is covered by the second document")
        m71 = [m for m in pkg["items"][1]["observation"]["document_mapping"]["mappings"] if m["clause_id"] == "7.1"][0]
        self.assertEqual(m71["excerpt"]["location"]["section"], "Vulnerability management")
        self.assertEqual(m71["source_doc"]["name"], "Backup-Standard.docx")
        self.assertTrue(bl.verify_package(pkg, blob_dir=os.path.join(tmp, "out", "blobs"), registry=None))


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


class Matching(unittest.TestCase):
    def setUp(self):
        self.doc = il.extract_document(DOC)
        self.fw = il.load_framework(open(R3, "rb").read(), R3)

    def test_bm25_ranks_the_right_paragraph(self):
        be = il.get_backend("bm25")
        be.index([(0, ch) for ch in self.doc["chunks"]])
        mfa = [c for c in self.fw["clauses"] if c["id"] == "03.05.03"][0]
        top = be.rank(mfa, k=3)
        self.assertIn("multi-factor authentication", self.doc["chunks"][top[0][0]]["text"])
        self.assertGreater(top[0][2], 0.0)
        self.assertLessEqual(top[0][2], 1.0)
        self.assertEqual(top, sorted(top, key=lambda r: -r[1]), "ranked by BM25 score")

    def test_confidence_floor_routes_to_gaps(self):
        props = il.propose(self.fw, [self.doc], il.get_backend("bm25"), floor=0.2)
        by = {p["clause_id"]: p for p in props}
        self.assertEqual(len(props), len(self.fw["clauses"]), "every clause gets a row: proposal or gap")
        self.assertEqual(by["03.05.03"]["status"], "proposed")
        self.assertIn("multi-factor", by["03.05.03"]["excerpt"]["text"])
        self.assertEqual(by["03.13.11"]["status"], "below_floor", "cryptography is not in the sample policy")
        strict = {p["clause_id"]: p for p in il.propose(self.fw, [self.doc], il.get_backend("bm25"), floor=0.99)}
        self.assertEqual(strict["03.05.03"]["status"], "below_floor", "the floor is configurable")
        for p in props:
            if p["status"] == "proposed":
                self.assertIn(p["excerpt"]["text"], POLICY_TEXT)
                self.assertGreaterEqual(p["confidence"], 0.2)

    def test_candidates_are_offered(self):
        props = il.propose(self.fw, [self.doc], il.get_backend("bm25"), floor=0.2, k=3)
        p = [p for p in props if p["clause_id"] == "03.05.03"][0]
        self.assertGreaterEqual(len(p["candidates"]), 1)
        self.assertLessEqual(len(p["candidates"]), 3)
        self.assertEqual(p["candidates"][0]["chunk"], p["excerpt"]["chunk"])
        scores = [c["score"] for c in p["candidates"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_deterministic(self):
        a = il.propose(self.fw, [self.doc], il.get_backend("bm25"), floor=0.2)
        b = il.propose(self.fw, [self.doc], il.get_backend("bm25"), floor=0.2)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_backends_are_pluggable_and_local_only(self):
        self.assertIn("bm25", il.BACKENDS)
        self.assertIn("keyword", il.BACKENDS)

        class Cloud(il.MatcherBackend):
            name, version, network = "cloud-test", "0", True
        il.BACKENDS["cloud-test"] = Cloud
        try:
            with self.assertRaises(il.MatcherError):
                il.get_backend("cloud-test")
        finally:
            del il.BACKENDS["cloud-test"]
        with self.assertRaises(il.MatcherError):
            il.get_backend("nope")

    def test_matcher_makes_no_network_calls(self):
        import socket
        real = socket.socket.connect

        def boom(*a, **k):
            raise AssertionError("the matcher opened a network connection")
        socket.socket.connect = boom
        try:
            il.propose(self.fw, [self.doc], il.get_backend("bm25"), floor=0.2)
        finally:
            socket.socket.connect = real

    def test_multiple_documents(self):
        p = make_docx(os.path.join(tempfile.mkdtemp(), "Crypto-Standard.docx"), [
            ("Heading1", "Cryptography"),
            (None, "Cryptographic mechanisms protecting CUI use FIPS-validated cryptography and approved modules.")])
        docx = il.extract_document(p)
        props = {x["clause_id"]: x for x in il.propose(self.fw, [self.doc, docx], il.get_backend("bm25"), floor=0.2)}
        self.assertEqual(props["03.13.11"]["status"], "proposed")
        self.assertEqual(props["03.13.11"]["excerpt"]["doc"], 1)
        self.assertEqual(props["03.13.11"]["excerpt"]["location"]["section"], "Cryptography")
        self.assertEqual(props["03.05.03"]["excerpt"]["doc"], 0)


def web(url, form=None, host=None):
    """(status, body) for a GET, or a POST when form is given; 303s are followed."""
    import http.client
    import urllib.error
    import urllib.parse
    import urllib.request
    if host:
        u = urllib.parse.urlsplit(url)
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
        c.putrequest("GET", u.path + "?" + u.query, skip_host=True)
        c.putheader("Host", host)
        c.endheaders()
        r = c.getresponse()
        try:
            return r.status, r.read().decode()
        finally:
            c.close()
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        with e:
            return e.code, e.read().decode()


def session_args(tmp, docs, framework, crosswalk=None, floor=0.2):
    return argparse.Namespace(doc=docs, framework=framework, framework_sha256=None, floor=floor, matcher="bm25",
                              crosswalk=crosswalk, subject="TestCo", box=None, sign=False, no_anchor=True,
                              home=os.path.join(tmp, ".beacon"), out_dir=os.path.join(tmp, "out"))


class ConfirmPage(unittest.TestCase):
    """Drives the confirm page over real HTTP on 127.0.0.1, as a reviewer's browser would."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.hostile = os.path.join(self.tmp, "hostile.md")
        open(self.hostile, "w").write(
            "## Remote access\n\nAll remote access requires multi-factor authentication "
            "<script>alert('x')</script> for every account.\n\n"
            "## Logs\n\nAudit logs are collected from every server and retained for one year.\n")
        self.args = session_args(self.tmp, [DOC, self.hostile], FW)
        self.sess = im.open_session(self.args)
        self.srv, self.url, self.review = ir.start(self.sess, lambda s: im.seal_session(s, self.args))
        self.base = self.url.split("?")[0]
        self.t = self.review.token

    def tearDown(self):
        self.srv.shutdown()

    def post(self, path, **form):
        form.setdefault("t", self.t)
        return web(self.base.rstrip("/") + path, form)

    def test_bound_to_loopback_with_random_port(self):
        self.assertEqual(self.srv.server_address[0], "127.0.0.1")
        self.assertNotEqual(self.srv.server_address[1], 0)
        self.assertGreaterEqual(len(self.t), 40)

    def test_token_gates_every_request(self):
        self.assertEqual(web(self.base)[0], 403)
        self.assertEqual(web(self.base + "?t=wrong")[0], 403)
        self.assertEqual(web(self.base.rstrip("/") + "/decide", {"t": "wrong", "clause": "6.3", "action": "confirm"})[0], 403)
        self.assertNotIn("6.3", self.sess["decisions"])
        self.assertEqual(web(self.url)[0], 200)

    def test_foreign_host_header_refused(self):
        self.assertEqual(web(self.url, host="evil.example:%d" % self.srv.server_address[1])[0], 403)

    def test_document_text_is_escaped(self):
        status, body = web(self.url)
        self.assertEqual(status, 200)
        self.assertNotIn("<script>alert", body)
        self.assertIn("&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;", body)

    def test_full_review_flow_seals_only_what_was_confirmed(self):
        # confirm 6.3, edit 8.2 down to one sentence, mark 11.2 not covered, supply 7.1 by hand,
        # leave 1.1 untouched
        self.assertEqual(self.post("/decide", clause="6.3", action="confirm")[0], 200)
        span = "Audit logs are collected from servers and critical applications and retained for at least one year."
        self.assertEqual(self.post("/decide", clause="8.2", action="edit", doc="0", span=span)[0], 200)
        self.assertEqual(self.post("/decide", clause="11.2", action="not_covered")[0], 200)
        self.assertEqual(self.post("/decide", clause="7.1", action="edit", doc="0",
                                   span="The IT team reviews and updates the asset inventory every quarter.")[0], 200)
        # a paraphrase is refused server-side and changes nothing
        status, body = self.post("/decide", clause="1.1", action="edit", doc="0",
                                 span="The company keeps an inventory of every asset.")
        self.assertEqual(status, 400)
        self.assertIn("not a verbatim substring", body)
        self.assertNotIn("1.1", self.sess["decisions"])
        # sealing needs a reviewer name
        self.assertEqual(self.post("/seal", reviewer="   ")[0], 400)
        status, body = self.post("/seal", reviewer="Jordan Doe")
        self.assertEqual(status, 200)
        self.assertIn("package_hash", body)
        # the token is spent
        self.assertEqual(web(self.url)[0], 410)
        self.assertEqual(self.post("/decide", clause="1.1", action="confirm")[0], 410)

        out = self.args.out_dir
        pkg = json.load(open(os.path.join(out, "package.json")))
        self.assertTrue(bl.verify_package(pkg, blob_dir=os.path.join(out, "blobs"), registry=None))
        maps = {m["clause_id"]: m for it in pkg["items"] if "document_mapping" in it["observation"]
                for m in it["observation"]["document_mapping"]["mappings"]}
        self.assertTrue(maps["6.3"]["human"]["confirmed"])
        self.assertEqual(maps["6.3"]["human"]["by"], "Jordan Doe")
        self.assertTrue(maps["6.3"]["human"]["at"])
        self.assertEqual(maps["8.2"]["excerpt"]["text"], span)
        self.assertEqual(maps["8.2"]["human"]["decision"], "edited")
        self.assertIn("proposed_excerpt", maps["8.2"])
        self.assertEqual(maps["7.1"]["excerpt"]["location"]["section"], "Asset management")
        self.assertTrue(maps["7.1"]["human"]["confirmed"])
        self.assertFalse(maps["1.1"]["human"]["confirmed"], "untouched proposals stay unconfirmed")
        self.assertIsNone(maps["1.1"]["human"]["by"])
        self.assertNotIn("11.2", maps)
        summary = [it for it in pkg["items"] if "document_mapping_summary" in it["observation"]][0]
        gaps = {g["clause_id"]: g for g in summary["observation"]["document_mapping_summary"]["gaps"]}
        self.assertEqual(gaps["11.2"]["reason"], "reviewer_marked_not_covered")
        self.assertEqual(gaps["11.2"]["by"], "Jordan Doe")
        for m in maps.values():
            src = [d for d in self.sess["docs"] if d["sha256"] == m["source_doc"]["sha256"]][0]
            self.assertIn(m["excerpt"]["text"], src["text"], "every sealed excerpt is verbatim")

    def test_seal_with_no_decisions_is_all_unconfirmed(self):
        self.assertEqual(self.post("/seal", reviewer="Jordan Doe")[0], 200)
        pkg = json.load(open(os.path.join(self.args.out_dir, "package.json")))
        for it in pkg["items"]:
            for m in it["observation"].get("document_mapping", {}).get("mappings", []):
                self.assertFalse(m["human"]["confirmed"])


class Crosswalk(unittest.TestCase):
    CW_R3 = os.path.join(HERE, "crosswalks", "DRAFT-nist-sp800-171r3-to-vcri-rubrics.json")
    CW_CIS = os.path.join(HERE, "crosswalks", "DRAFT-cis-8.1-to-vcri-rubrics.json")

    def test_load_and_refusals(self):
        r3 = il.load_framework(open(R3, "rb").read(), R3)
        cw = il.load_crosswalk(self.CW_R3, r3)
        self.assertEqual(cw["status"], "draft-unratified")
        self.assertEqual(cw["sha256"], file_sha(self.CW_R3))
        self.assertIn("03.05.03", cw["entries"])
        with self.assertRaises(il.CatalogError):
            il.load_crosswalk(self.CW_CIS, r3)  # wrong framework
        bad = os.path.join(tempfile.mkdtemp(), "bad.json")
        json.dump({"_schema": il.CROSSWALK_SCHEMA, "framework": {"ids": ["nist-sp800-171r3"]},
                   "entries": [{"clause_id": "99.99.99", "targets": [{"rubric": "people-v1", "key": "2a"}]}]},
                  open(bad, "w"))
        with self.assertRaises(il.CatalogError):
            il.load_crosswalk(bad, r3)  # clause not in the catalog

    def test_cis_draft_is_small_labeled_and_bound_to_the_official_catalog(self):
        doc = json.load(open(self.CW_CIS))
        self.assertIn("draft", doc["status"])
        self.assertIn("NOT ratified", doc["_status"])
        self.assertLessEqual(len(doc["entries"]), 10, "a handful of examples, not a crosswalk")
        self.assertEqual(doc["framework"]["ids"], ["cis-8.1"])
        with self.assertRaises(il.CatalogError):
            il.load_crosswalk(self.CW_CIS, il.load_framework(open(FW, "rb").read(), FW))  # the sample is not CIS

    def test_resolve_slot(self):
        emap = im.load_emap()
        self.assertEqual(il.resolve_slot(emap, "people-v1", "2a"), "people-v1:mfa")
        self.assertIsNone(il.resolve_slot(emap, "technology-v1", "6b"))

    def run_review(self, decide):
        tmp = tempfile.mkdtemp()
        args = session_args(tmp, [DOC], R3, crosswalk=self.CW_R3)
        sess = im.open_session(args)
        srv, url, review = ir.start(sess, lambda s: im.seal_session(s, args))
        base = url.split("?")[0].rstrip("/")
        try:
            for form in decide:
                form = dict(form, t=review.token)
                self.assertEqual(web(base + "/decide", form)[0], 200, form)
            self.assertEqual(web(base + "/seal", {"t": review.token, "reviewer": "Jordan Doe"})[0], 200)
        finally:
            srv.shutdown()
        return args.out_dir, json.load(open(os.path.join(args.out_dir, "package.json")))

    def test_confirmed_mappings_reach_the_scorer_as_stated_cap_1(self):
        out, pkg = self.run_review([
            {"clause": "03.05.03", "action": "confirm"},
            {"clause": "03.06.01", "action": "edit", "doc": "0",
             "span": "Logging is enabled across systems to support detection and investigation of incidents."},
        ])
        slots = [it["subcriterion"] for it in pkg["items"]]
        self.assertIn("people-v1:mfa", slots)
        mfa = [it for it in pkg["items"] if it["subcriterion"] == "people-v1:mfa"][0]
        self.assertEqual(mfa["epistemic"], "subject_claim")
        self.assertTrue(mfa["observation"]["stated"]["human_confirmed"])
        self.assertEqual(mfa["observation"]["stated"]["clauses"][0]["confirmed_by"], "Jordan Doe")
        self.assertEqual(mfa["observation"]["stated"]["framework"]["catalog_sha256"], file_sha(R3))
        self.assertEqual(mfa["observation"]["stated"]["crosswalk"]["sha256"], file_sha(self.CW_R3))
        self.assertEqual(mfa["mapping"]["status"], "mapped")
        unm = [it for it in pkg["items"] if it["subcriterion"] == "unmapped" and "stated" in it["observation"]]
        self.assertEqual(len(unm), 1, "incident handling routes to technology-v1/6b, which has no slot")
        self.assertEqual(unm[0]["mapping"]["candidate_rubric_keys"], ["technology-v1:6b"])
        # 03.04.10 etc. were proposed but not confirmed: they must not reach a slot
        self.assertNotIn("technology-v1:1.1a", slots)

        import subprocess
        import sys
        r = subprocess.run([sys.executable, os.path.join(HERE, "score.py"), os.path.join(out, "package.json"),
                            "--json", os.path.join(out, "score.json")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        res = json.load(open(os.path.join(out, "score.json")))
        sub = [s for d in res["rubrics"]["people-v1"]["dimensions"] for s in d["subcriteria"] if s["key"] == "2a"][0]
        self.assertEqual(sub["level"], 1)
        self.assertEqual(sub["evidence"]["class"], "stated")
        self.assertEqual(sub["evidence"]["cap"], 1)
        self.assertEqual(list(res["rubrics"]), ["people-v1"], "only the confirmed, slotted clause scores")
        self.assertTrue(any("technology-v1:6b" in json.dumps(g) or g["slot"] == "unmapped" for g in res["gaps"]))

    def test_nothing_confirmed_nothing_routed(self):
        out, pkg = self.run_review([])
        self.assertFalse([it for it in pkg["items"] if "stated" in it["observation"]])


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
