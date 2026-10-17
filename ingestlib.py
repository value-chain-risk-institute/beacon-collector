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
            out.append((label + " " if label else "") + prose)
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
