#!/usr/bin/env python3
"""
ingestlib.py, the document ingester's library: framework catalogs, document text
extraction, the local matcher, and the crosswalk to scorer slots. No CLI here
(ingestmode.py), no HTTP here (ingestreview.py), no sealing here (beaconlib).

What this file may and may not do, in the house's terms:
  - It PROPOSES where in a document a framework clause appears to be addressed and
    quotes that span verbatim with a findable location. It never says whether the
    policy is good, sufficient, true or followed.
  - Nothing about a document leaves the machine. The only network access in this
    file is fetch_framework() downloading a public framework catalog; the matcher
    backends are local by declaration and the open build refuses any that is not.
  - Stdlib only, except pypdf for .pdf, which is optional and imported lazily.
"""
import hashlib
import io
import json
import math
import os
import re
import urllib.request
import zipfile
from xml.etree import ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG_DIR = os.path.join(HERE, "catalogs")
MAX_CATALOG_BYTES = 32 * 1024 * 1024


class CatalogError(Exception):
    pass


class DocumentError(Exception):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- catalogs

def load_index(catalog_dir=CATALOG_DIR):
    path = os.path.join(catalog_dir, "index.json")
    if not os.path.exists(path):
        return {}
    return json.load(open(path)).get("frameworks", {})


def _prop(obj, name):
    for p in obj.get("props", []) or []:
        if p.get("name") == name:
            return p.get("value")
    return None


def _clause_id(control):
    """A reviewer-facing id from the OSCAL label: 'CIS Safeguard 1.1' -> '1.1',
    'Account Management (03.01.01)' -> '03.01.01', 'GV.OC-01' -> 'GV.OC-01'.
    Falls back to the OSCAL id, which is always kept beside it as oscal_id."""
    label = _prop(control, "label") or ""
    found = re.findall(r"[\w.\-]*\d[\w.\-]*", label)
    return found[-1] if found else control["id"]


def _render_param(param):
    sel = param.get("select")
    if isinstance(sel, dict) and sel.get("choice"):
        how = "one or more" if sel.get("how-many") == "one-or-more" else "one"
        return "[Selection (%s): %s]" % (how, "; ".join(_render_prose(c, {}) for c in sel["choice"]))
    return "[Assignment: %s]" % (param.get("usage") or param.get("label") or param.get("id"))


def _render_prose(prose, params):
    def sub(m):
        p = params.get(m.group(1).strip())
        return _render_param(p) if p else "[Assignment: %s]" % m.group(1).strip()
    return re.sub(r"\{\{\s*insert:\s*param,\s*([^}]+?)\s*\}\}", sub, prose or "").strip()


def _statement_text(parts, params):
    """Statement prose and its items, in order. Guidance, examples and assessment
    objectives are not the clause and are left out."""
    out = []

    def walk(part, depth):
        prose = _render_prose(part.get("prose"), params)
        if prose:
            label = _prop(part, "label") if depth else None
            if label:
                # 'SR-03.02.01.a.01' -> '1.': the printed form, not the machine id
                last = re.split(r"[.\-]", label)[-1]
                label = (last.lstrip("0") or "0") if last.isdigit() else last
            out.append((label + ". " if label else "") + prose)
        for sp in part.get("parts", []) or []:
            if sp.get("name") in ("item", "statement"):
                walk(sp, depth + 1)

    for p in parts or []:
        if p.get("name") == "statement":
            walk(p, 0)
    return "\n".join(out)


def _oscal_clauses(catalog):
    params = {}

    def collect_params(controls):
        for c in controls or []:
            for p in c.get("params", []) or []:
                params[p["id"]] = p
            collect_params(c.get("controls"))

    def groups_walk(groups, fn):
        for g in groups or []:
            fn(g)
            groups_walk(g.get("groups"), fn)

    groups_walk(catalog.get("groups"), lambda g: collect_params(g.get("controls")))
    collect_params(catalog.get("controls"))
    for p in catalog.get("params", []) or []:
        params[p["id"]] = p

    clauses = []

    def controls_walk(controls, path):
        for c in controls or []:
            if (_prop(c, "status") or "").lower() == "withdrawn":
                continue
            children = [k for k in c.get("controls", []) or [] if (_prop(k, "status") or "").lower() != "withdrawn"]
            if children:
                # a parent (CIS Control 1, CSF category) organizes its leaves; the
                # leaves are the clauses a policy is mapped to
                controls_walk(children, path + [c.get("title", "")])
                continue
            text = _statement_text(c.get("parts"), params)
            if not text and not c.get("title"):
                continue
            clauses.append({"id": _clause_id(c), "oscal_id": c["id"], "title": c.get("title", ""),
                            "text": text, "class": c.get("class"), "group_path": [x for x in path if x]})

    def top(groups, path):
        for g in groups or []:
            controls_walk(g.get("controls"), path + [g.get("title", "")])
            top(g.get("groups"), path + [g.get("title", "")])

    top(catalog.get("groups"), [])
    controls_walk(catalog.get("controls"), [])
    return clauses


def _slug(text):
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:48] or "framework"


def load_framework(raw: bytes, origin: str, framework_id: str = None, catalog_dir=CATALOG_DIR) -> dict:
    """Normalize a catalog to {id, version, title, format, catalog_sha256, clauses:
    [{id, oscal_id, title, text, group_path}]}. Accepts an OSCAL catalog (JSON,
    controls nested in groups and controls) or the simple {id, version, clauses}
    format. The id is the index id bound to this exact hash when there is one."""
    digest = sha256(raw)
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise CatalogError("%s is not JSON: %s" % (origin, e))
    by_hash = {v.get("sha256"): k for k, v in load_index(catalog_dir).items()}
    if isinstance(doc, dict) and isinstance(doc.get("catalog"), dict):
        cat = doc["catalog"]
        meta = cat.get("metadata", {})
        clauses = _oscal_clauses(cat)
        fw = {"id": framework_id or by_hash.get(digest) or _slug(meta.get("title")),
              "version": meta.get("version"), "title": meta.get("title"),
              "last_modified": meta.get("last-modified"), "oscal_version": meta.get("oscal-version"),
              "format": "oscal-catalog"}
    elif isinstance(doc, dict) and doc.get("id") and isinstance(doc.get("clauses"), list):
        clauses = [{"id": str(c["id"]), "oscal_id": None, "title": c.get("title", ""), "text": c.get("text", ""),
                    "class": None, "group_path": []} for c in doc["clauses"]]
        fw = {"id": framework_id or by_hash.get(digest) or doc["id"], "version": doc.get("version"),
              "title": doc.get("title") or doc.get("source"), "format": "simple"}
    else:
        raise CatalogError("%s is neither an OSCAL catalog ({catalog: ...}) nor {id, version, clauses}" % origin)
    if not clauses:
        raise CatalogError("%s contains no clauses" % origin)
    seen = {}
    for c in clauses:
        seen[c["id"]] = seen.get(c["id"], 0) + 1
    dupes = [k for k, n in seen.items() if n > 1]
    if dupes:
        # two clauses under one reviewer id would make a mapping ambiguous; fall back
        # to the OSCAL ids, which the format guarantees unique
        for c in clauses:
            c["id"] = c["oscal_id"] or c["id"]
    fw["catalog_sha256"] = digest
    fw["clauses"] = clauses
    return fw


def _download(url, allow_http):
    if not (url.startswith("https://") or (allow_http and url.startswith("http://"))):
        raise CatalogError("refusing to fetch %s: https only (a catalog is what clauses are matched against)" % url)
    req = urllib.request.Request(url, headers={"User-Agent": "beacon-document-ingester/0.2"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read(MAX_CATALOG_BYTES + 1)
    except OSError as e:
        raise CatalogError("could not fetch %s: %s" % (url, e))
    if len(raw) > MAX_CATALOG_BYTES:
        raise CatalogError("%s is larger than %d bytes; refusing" % (url, MAX_CATALOG_BYTES))
    return raw


def fetch_framework(spec, home, expected_sha256=None, allow_http=False, catalog_dir=CATALOG_DIR,
                    framework_id=None) -> dict:
    """Load the framework a user picked, from (in order): an id in catalogs/index.json
    (vendored file, or the pinned URL with a local cache), an https URL, or a local
    path. This is the only network access in the ingester, and it fetches a public
    catalog, never a document. `expected_sha256` pins the bytes; an index entry
    always pins. The catalog's sha256 goes into every item sealed against it."""
    index = load_index(catalog_dir)
    source = {"spec": spec}
    if spec in index:
        entry = index[spec]
        pin = expected_sha256 or entry.get("sha256")
        cache = os.path.join(home, "catalogs", "sha256-%s.json" % pin) if pin else None
        if entry.get("path"):
            raw = open(os.path.join(catalog_dir, entry["path"]), "rb").read()
            source.update(kind="index", path=entry["path"], url=entry.get("url"))
        elif cache and os.path.exists(cache):
            raw = open(cache, "rb").read()
            source.update(kind="index", url=entry.get("url"), cached=True)
        else:
            raw = _download(entry["url"], allow_http)
            source.update(kind="index", url=entry["url"], cached=False)
        framework_id = framework_id or spec
    elif re.match(r"^https?://", spec):
        pin = expected_sha256
        raw = _download(spec, allow_http)
        source.update(kind="url", url=spec)
    elif os.path.exists(spec):
        pin = expected_sha256
        raw = open(spec, "rb").read()
        source.update(kind="path", path=os.path.abspath(spec))
    else:
        known = ", ".join(sorted(index)) or "none"
        raise CatalogError("framework %r is not a known id (%s), an https URL, or a file" % (spec, known))
    digest = sha256(raw)
    if pin and digest != pin:
        raise CatalogError("catalog %s has sha256 %s, expected %s; refusing (re-pin deliberately if the "
                           "publisher changed it)" % (spec, digest, pin))
    if source["kind"] in ("url", "index") and not source.get("path"):
        os.makedirs(os.path.join(home, "catalogs"), exist_ok=True)
        cpath = os.path.join(home, "catalogs", "sha256-%s.json" % digest)
        if not os.path.exists(cpath):
            with open(cpath, "wb") as f:
                f.write(raw)
    fw = load_framework(raw, spec, framework_id=framework_id, catalog_dir=catalog_dir)
    fw["source"] = source
    return fw


# ---------------------------------------------------------------- documents
#
# A document becomes {name, sha256, kind, text, chunks, extraction}. `text` is the
# extracted text the reviewer's spans are checked against; every chunk is
# text[start:end] exactly, so an excerpt is verbatim by construction and an edited
# span is accepted only if it is a substring of `text`. For .md/.txt `text` is the
# file itself (decoded); for .docx/.pdf it is the extracted paragraphs joined by
# blank lines, and the sealed blob is the original file so anyone can re-extract.

MAX_DOC_BYTES = 64 * 1024 * 1024
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
DOC_KINDS = {".md": "markdown", ".markdown": "markdown", ".txt": "text", ".docx": "docx", ".pdf": "pdf"}


def have_pypdf():
    try:
        import pypdf  # noqa: F401
        return True
    except ImportError:
        return False


def _blocks(text):
    """(start, end) of each blank-line-separated block, trimmed, in order."""
    for m in re.finditer(r"\S(?:.*?)(?=\n[ \t]*\n|\Z)", text, re.S):
        s, e = m.start(), m.end()
        while e > s and text[e - 1].isspace():
            e -= 1
        yield s, e


def _looks_like_heading(line):
    line = line.strip()
    return 0 < len(line) <= 80 and "\n" not in line and not re.search(r"[.;,]$", line) and len(line.split()) <= 10


def _chunks_from_text(text, markdown):
    chunks, section, para = [], None, 0
    blocks = list(_blocks(text))
    for i, (s, e) in enumerate(blocks):
        block = text[s:e]
        first, _, rest = block.partition("\n")
        if markdown and re.match(r"#{1,6}\s", first):
            section = re.sub(r"^#{1,6}\s+|\s+#*$", "", first).strip()
            if not rest.strip():
                continue
            s = s + len(first) + 1 + (len(rest) - len(rest.lstrip()))
            block = text[s:e]
        elif not markdown and i + 1 < len(blocks) and _looks_like_heading(block):
            section = block.strip()
            continue
        para += 1
        chunks.append({"start": s, "end": e, "text": block, "section": section, "page": None, "paragraph": para})
    return chunks


def _docx_paragraphs(raw):
    try:
        z = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise DocumentError("not a .docx (not a zip archive)")
    names = set(z.namelist())
    if "word/document.xml" not in names:
        raise DocumentError("not a .docx (no word/document.xml)")

    def part(name):
        info = z.getinfo(name)
        if info.file_size > MAX_DOC_BYTES:
            raise DocumentError("%s expands to %d bytes; refusing" % (name, info.file_size))
        data = z.read(name)
        if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
            # OOXML never carries a DTD; one here is an entity-expansion attempt
            raise DocumentError("%s carries a DTD/entity declaration; refusing untrusted XML" % name)
        try:
            return ET.fromstring(data)
        except ET.ParseError as e:
            raise DocumentError("%s is not well-formed XML: %s" % (name, e))

    style_names = {}
    if "word/styles.xml" in names:
        for st in part("word/styles.xml").iter(W + "style"):
            nm = st.find(W + "name")
            style_names[st.get(W + "styleId")] = (nm.get(W + "val") if nm is not None else "") or ""
    body = part("word/document.xml").find(W + "body")
    out = []
    for p in body.iter(W + "p") if body is not None else []:
        buf = []
        for node in p.iter():
            if node.tag == W + "t":
                buf.append(node.text or "")
            elif node.tag == W + "tab":
                buf.append("\t")
            elif node.tag in (W + "br", W + "cr"):
                buf.append("\n")
        text = "".join(buf).strip()
        ppr = p.find(W + "pPr")
        style = ""
        heading = False
        if ppr is not None:
            ps = ppr.find(W + "pStyle")
            if ps is not None:
                sid = ps.get(W + "val") or ""
                style = style_names.get(sid, sid)
            heading = ppr.find(W + "outlineLvl") is not None
        heading = heading or bool(re.match(r"^(heading\s*\d*|title|subtitle)$", style.strip().lower()))
        if text:
            out.append((text, heading))
    return out


def _pdf_pages(raw):
    if not have_pypdf():
        raise DocumentError("reading .pdf needs the optional pypdf package, which is not installed: "
                            "pip install -r requirements-optional.txt (or pip install 'pypdf>=4'). "
                            "Alternatively export the policy as .docx or .md and ingest that.")
    import pypdf
    try:
        reader = pypdf.PdfReader(io.BytesIO(raw))
        return [(pg.extract_text() or "") for pg in reader.pages]
    except Exception as e:  # pypdf raises a zoo of types on malformed input
        raise DocumentError("could not read the PDF: %s: %s" % (type(e).__name__, e))


def _split_long(text, s, e, limit=700):
    """A PDF page often arrives with no blank lines at all. Break an over-long block
    at line ends that close a sentence, so a span is a paragraph, not a page."""
    if e - s <= limit:
        return [(s, e)]
    out, start, pos = [], s, s
    for m in re.finditer(r"[.!?:]\n", text[s:e]):
        cut = s + m.start() + 1
        if cut - start >= 200:
            out.append((start, cut))
            start = cut + 1
        pos = cut
    out.append((start, e))
    return [(a, b) for a, b in out if text[a:b].strip()]


def extract_document(path):
    ext = os.path.splitext(path)[1].lower()
    kind = DOC_KINDS.get(ext)
    if not kind:
        raise DocumentError("%s: unsupported type %r (supported: %s)" % (path, ext, ", ".join(sorted(DOC_KINDS))))
    if not os.path.exists(path):
        raise DocumentError("document not found: %s" % path)
    if os.path.getsize(path) > MAX_DOC_BYTES:
        raise DocumentError("%s is larger than %d bytes; refusing" % (path, MAX_DOC_BYTES))
    raw = open(path, "rb").read()
    if kind in ("markdown", "text"):
        text = raw.decode("utf-8-sig", "replace")
        chunks = _chunks_from_text(text, markdown=(kind == "markdown"))
        method = "utf-8 text, blank-line paragraphs" + (", ATX headings as sections" if kind == "markdown" else
                                                         ", short title-like lines as sections")
    elif kind == "docx":
        paras = _docx_paragraphs(raw)
        pieces, chunks, section, pos = [], [], None, 0
        for n, (ptext, heading) in enumerate(paras, 1):
            if pieces:
                pos += 2
            start = pos
            pieces.append(ptext)
            pos += len(ptext)
            if heading:
                section = ptext
                continue
            chunks.append({"start": start, "end": pos, "text": ptext, "section": section, "page": None,
                           "paragraph": n})
        text = "\n\n".join(pieces)
        method = "stdlib zipfile + WordprocessingML; paragraph = non-empty w:p in body order (tables included); " \
                 "headings by style; .docx has no fixed pages"
    else:
        pages = _pdf_pages(raw)
        text = ""
        chunks = []
        for pno, ptext in enumerate(pages, 1):
            if text:
                text += "\n\n"
            base = len(text)
            text += ptext
            para = 0
            for s, e in _blocks(ptext):
                for a, b in _split_long(ptext, s, e):
                    para += 1
                    chunks.append({"start": base + a, "end": base + b, "text": ptext[a:b], "section": None,
                                   "page": pno, "paragraph": para})
        import pypdf
        method = "pypdf %s extract_text per page; paragraph index is per page" % pypdf.__version__
    if not chunks:
        raise DocumentError("%s has no readable text (a scanned PDF needs OCR first)" % path)
    for i, ch in enumerate(chunks, 1):
        ch["index"] = i
    return {"name": os.path.basename(path), "sha256": sha256(raw), "kind": kind, "raw": raw, "text": text,
            "chunks": chunks, "extraction": {"method": method, "ingester": "0.2.0"}}


def location(doc, chunk):
    return {"doc": doc["name"], "doc_sha256": doc["sha256"], "page": chunk.get("page"),
            "section": chunk.get("section"), "paragraph": chunk.get("paragraph"),
            "chars": [chunk["start"], chunk["end"]]}


def location_text(doc, chunk):
    bits = [doc["name"]]
    if chunk.get("page"):
        bits.append("p.%d" % chunk["page"])
    if chunk.get("section"):
        bits.append("section '%s'" % chunk["section"])
    bits.append("paragraph %d" % chunk["paragraph"])
    return ", ".join(bits)


def find_span(doc, span):
    """Locate a reviewer's edited span. It must be a verbatim substring of the
    extracted text; returns (start, end, containing chunk) or None."""
    span = (span or "").replace("\r\n", "\n").strip()
    if not span:
        return None
    at = doc["text"].find(span)
    if at < 0:
        return None
    end = at + len(span)
    host = None
    for ch in doc["chunks"]:
        if ch["start"] <= at < ch["end"] or (host is None and ch["start"] >= at):
            host = ch
            break
    host = host or doc["chunks"][-1]
    return at, end, host


# ---------------------------------------------------------------- matcher
#
# A backend ranks document chunks for one clause. It is the only piece meant to be
# swapped (embeddings, an LLM picking the span) and it never touches packaging,
# confirmation or sealing. Every backend declares `network`; the open build refuses
# any backend that declares True, so "nothing about a document leaves the machine"
# is enforced at selection time, not left to the backend's good manners.

STOPWORDS = set("""a an the and or of to for in on at by with from as is are be been being this that these those
it its their your our his her they you we i he she them us me my if then than so such not no nor only also any all
each every both either neither which who whom whose what when where why how may might must shall should would could
can will do does did done have has had having into over under between within without about against during before
after above below up down out off per via use used using ensure ensured maintain maintained provide provided
including include includes following organization organizational defined assignment selection enterprise""".split())
TOKEN = re.compile(r"[a-z0-9]+")


def stem(t):
    """Crude, deterministic folding so 'backups'/'backup', 'logging'/'logs' and
    'authentication'/'authenticated' meet: strip a plural or -ed/-ing ending (undoing
    a doubled final consonant), then keep the first six letters. Not Porter; good
    enough to rank, and a human confirms every span anyway."""
    if t.isdigit():
        return t
    if t.endswith("ies") and len(t) > 4:
        t = t[:-3] + "y"
    elif t.endswith("s") and not t.endswith("ss") and len(t) > 3:
        t = t[:-1]
    for suf in ("ing", "ed"):
        if t.endswith(suf) and len(t) - len(suf) >= 3:
            t = t[: -len(suf)]
            if len(t) > 3 and t[-1] == t[-2] and t[-1] not in "lsz":
                t = t[:-1]
            break
    return t[:6]


def tokens(text):
    return [stem(t) for t in TOKEN.findall((text or "").lower()) if t not in STOPWORDS and len(t) > 2]


def clause_query(clause):
    """Clause text = title + statement prose, as (title, statement). The title is
    dropped when it is only the id, as CSF subcategory titles are."""
    title = clause.get("title", "")
    return ("" if title == clause.get("id") else title), clause.get("text", "")


class MatcherError(Exception):
    pass


class MatcherBackend:
    """Interface. index() receives [(doc_position, chunk)]; rank() returns up to k
    (position in that list, score, confidence 0..1), best first. Confidence is the
    backend's own calibrated number for the confidence floor; it is not a probability
    and not a judgment of the policy."""
    name = "abstract"
    version = "0"
    network = False

    def index(self, items):
        self.items = list(items)

    def rank(self, clause, k=3):
        raise NotImplementedError


class KeywordBackend(MatcherBackend):
    """v0.1 baseline: recall of the clause's distinctive words inside the chunk."""
    name, version = "local-keyword-overlap", "0.1.0"

    def index(self, items):
        super().index(items)
        self.toks = [set(tokens(ch["text"])) for _, ch in self.items]

    def rank(self, clause, k=3):
        q = set(tokens(" ".join(clause_query(clause))))
        if not q:
            return []
        scored = [(i, round(sum(1 for t in q if t in st) / len(q), 3)) for i, st in enumerate(self.toks)]
        scored = [(i, s, s) for i, s in scored if s > 0]
        scored.sort(key=lambda r: (-r[1], r[0]))
        return scored[:k]


class BM25Backend(MatcherBackend):
    """Okapi BM25 over chunks (stdlib). Ranking is BM25. Confidence is 0..1 and
    comparable across clauses (raw BM25 is neither): the mean of the IDF-weighted
    share of the clause title's terms and of its statement's terms found in the
    chunk. Terms the document never uses carry the maximum IDF, so a clause about
    something the policy never mentions lands below the floor."""
    name, version = "local-bm25", "0.2.0"
    k1, b = 1.5, 0.75

    def index(self, items):
        super().index(items)
        self.tf = []
        self.df = {}
        for _, ch in self.items:
            toks = tokens(ch["text"])
            counts = {}
            for t in toks:
                counts[t] = counts.get(t, 0) + 1
            self.tf.append((counts, len(toks)))
            for t in counts:
                self.df[t] = self.df.get(t, 0) + 1
        self.n = len(self.items)
        self.avgdl = (sum(dl for _, dl in self.tf) / self.n) if self.n else 0.0

    def idf(self, t):
        df = self.df.get(t, 0)
        return math.log((self.n - df + 0.5) / (df + 0.5) + 1.0)

    def coverage(self, terms, counts):
        """IDF-weighted share of `terms` present in a chunk, 0..1."""
        if not terms:
            return None
        den = sum(self.idf(t) for t in terms)
        return sum(self.idf(t) for t in terms if t in counts) / den if den else 0.0

    def rank(self, clause, k=3):
        title, text = clause_query(clause)
        tq, sq = set(tokens(title)), set(tokens(text))
        q = sorted(tq | sq)
        if not q or not self.n:
            return []
        # title terms count twice in the BM25 query: a clause's title is its most
        # distinctive vocabulary, its statement prose the most diluted
        weight = {t: (2.0 if t in tq else 1.0) for t in q}
        out = []
        for i, (counts, dl) in enumerate(self.tf):
            score = 0.0
            for t in q:
                f = counts.get(t)
                if f:
                    score += weight[t] * self.idf(t) * f * (self.k1 + 1) / (
                        f + self.k1 * (1 - self.b + self.b * dl / (self.avgdl or 1)))
            if score <= 0:
                continue
            # confidence: the mean of title coverage and statement coverage, so a
            # long statement does not drown a span that plainly answers the title
            parts = [c for c in (self.coverage(tq, counts), self.coverage(sq, counts)) if c is not None]
            out.append((i, round(score, 4), round(sum(parts) / len(parts), 3)))
        out.sort(key=lambda r: (-r[1], r[0]))
        return out[:k]


BACKENDS = {"bm25": BM25Backend, "keyword": KeywordBackend}


def get_backend(name):
    cls = BACKENDS.get(name)
    if cls is None:
        raise MatcherError("unknown matcher %r (have: %s)" % (name, ", ".join(sorted(BACKENDS))))
    if cls.network:
        raise MatcherError("matcher %r declares network access; the open VCRI Collector is local-only "
                           "(a cloud backend belongs to the CRC build, on authorized documents)" % name)
    return cls()


def excerpt_record(docs, d, ch):
    doc = docs[d]
    return {"doc": d, "chunk": ch["index"], "text": ch["text"], "location": location(doc, ch),
            "location_text": location_text(doc, ch)}


def propose(fw, docs, backend, floor=0.2, k=3):
    """One row per framework clause: the best verbatim chunk and up to k candidates,
    status 'proposed' at or above the floor, 'below_floor' otherwise (a gap the
    reviewer can still fill by hand). Deterministic for a given input."""
    items = [(d, ch) for d, doc in enumerate(docs) for ch in doc["chunks"]]
    backend.index(items)
    rows = []
    for clause in fw["clauses"]:
        ranked = backend.rank(clause, k=k)
        cands = [{"doc": items[i][0], "chunk": items[i][1]["index"], "score": s, "confidence": c}
                 for i, s, c in ranked]
        best = ranked[0] if ranked else None
        conf = best[2] if best else 0.0
        row = {"clause_id": clause["id"], "oscal_id": clause.get("oscal_id"), "clause_title": clause.get("title", ""),
               "clause_text": clause.get("text", ""), "confidence": conf, "candidates": cands,
               "status": "proposed" if best and conf >= floor else "below_floor", "excerpt": None}
        if best:
            d, ch = items[best[0]]
            row["excerpt"] = excerpt_record(docs, d, ch)
        rows.append(row)
    return rows
