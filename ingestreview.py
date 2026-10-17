#!/usr/bin/env python3
"""
ingestreview.py, the document ingester's confirm page: the only screen (DESIGN, "The UI").

A local page listing clause -> proposed verbatim excerpt -> confidence, with Confirm,
Edit span, Not covered, a reviewer name and "Seal package". It exists because an
automated mapping needs a human to confirm it; it is not a console.

Safety, because the documents are untrusted input and the page holds a policy:
  - bound to 127.0.0.1 on a random port; requests whose Host header is not that
    address are refused (DNS rebinding);
  - a random one-time token in the URL gates every request, is compared in constant
    time, and dies when the package is sealed;
  - every piece of document and catalog text is HTML-escaped; no script on the page;
    a CSP forbids scripts, frames and off-origin form posts; no-referrer, no-store;
  - an edited span is accepted only if it is a verbatim substring of the extracted
    document text, checked here on the server, never trusted from the browser;
  - only rows a named reviewer confirmed or edited are sealed human.confirmed=true.

Stdlib only. No score.
"""
import hmac
import html
import secrets
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import beaconlib as bl
import ingestlib as il

MAX_BODY = 1024 * 1024
MAX_REVIEWER = 120
ACTIONS = ("confirm", "edit", "not_covered", "reset")

CSS = """
:root{--bg:#fbfaf7;--fg:#1d1d1b;--muted:#6b6a65;--line:#dedcd5;--card:#fff;--ok:#1f6f43;--gap:#9a3b1b;--accent:#2b4c7e}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--muted:#a3a29b;--line:#34332f;--card:#1f1f1d;--ok:#6fcf97;--gap:#f2a07b;--accent:#8fb3e8}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;margin:0 auto;max-width:980px;padding:16px}
h1{font-size:20px;margin:8px 0}.meta{color:var(--muted);font-size:13px}
.row{background:var(--card);border:1px solid var(--line);border-radius:6px;margin:12px 0;padding:12px}
.cid{font-weight:600}.badge{font-size:12px;border:1px solid var(--line);border-radius:10px;padding:1px 8px;margin-left:6px}
.confirmed{color:var(--ok);border-color:var(--ok)}.gap{color:var(--gap);border-color:var(--gap)}
blockquote{border-left:3px solid var(--accent);margin:8px 0;padding:4px 10px;white-space:pre-wrap}
.loc{color:var(--muted);font-size:13px}form{display:inline}button{margin:4px 6px 0 0}
textarea{width:100%;min-height:80px;font:inherit}details{margin-top:6px}
.err{border:1px solid var(--gap);color:var(--gap);padding:10px;border-radius:6px}
.seal{border-top:2px solid var(--line);margin-top:24px;padding-top:12px}
"""


def esc(s):
    return html.escape("" if s is None else str(s), quote=True)


class Review:
    """State for one review session: the proposals, the decisions, the token."""

    def __init__(self, sess, seal_fn):
        self.sess = sess
        self.seal_fn = seal_fn
        self.token = secrets.token_urlsafe(32)
        self.rows = {r["clause_id"]: r for r in sess["rows"]}
        self.lock = threading.Lock()
        self.sealed = None
        self.done = threading.Event()

    def decide(self, form):
        """Apply one decision. Returns None, or an error message for the reviewer."""
        cid = form.get("clause", "")
        action = form.get("action", "")
        row = self.rows.get(cid)
        if row is None or action not in ACTIONS:
            return "unknown clause or action"
        now = bl.utcnow()
        if action == "reset":
            self.sess["decisions"].pop(cid, None)
            return None
        if action == "confirm":
            if not row.get("excerpt"):
                return "clause %s has no proposed excerpt to confirm; use Edit span to supply one" % cid
            self.sess["decisions"][cid] = {"action": "confirm", "at": now}
            return None
        if action == "not_covered":
            self.sess["decisions"][cid] = {"action": "not_covered", "at": now}
            return None
        try:
            d = int(form.get("doc", "0"))
            doc = self.sess["docs"][d]
        except (ValueError, IndexError):
            return "unknown document"
        found = il.find_span(doc, form.get("span", ""))
        if not found:
            return ("the edited span for %s is not a verbatim substring of %s; nothing was changed. "
                    "Copy the exact words from the document." % (cid, doc["name"]))
        a, b, host = found
        loc = il.location(doc, host)
        loc["chars"] = [a, b]
        self.sess["decisions"][cid] = {"action": "edit", "at": now, "excerpt": {
            "doc": d, "chunk": host["index"], "text": doc["text"][a:b], "location": loc,
            "location_text": il.location_text(doc, host)}}
        return None

    def seal(self, reviewer):
        reviewer = " ".join((reviewer or "").split())
        if not reviewer or len(reviewer) > MAX_REVIEWER:
            return None, "a reviewer name (1 to %d characters) is required to seal" % MAX_REVIEWER
        self.sess["reviewer"] = reviewer
        package, out_path, mappings, gaps = self.seal_fn(self.sess)
        self.sealed = {"package_hash": package["seal"]["package_hash"], "path": out_path,
                       "confirmed": sum(1 for m in mappings if m["human"]["confirmed"]),
                       "unconfirmed": sum(1 for m in mappings if not m["human"]["confirmed"]),
                       "gaps": len(gaps)}
        return self.sealed, None

    # ------------------------------------------------------------ rendering

    def state(self, row):
        d = self.sess["decisions"].get(row["clause_id"])
        if d:
            return {"confirm": ("confirmed", "confirmed"), "edit": ("confirmed (edited span)", "confirmed"),
                    "not_covered": ("not covered", "gap")}[d["action"]]
        if row["status"] == "proposed":
            return ("proposed, unconfirmed", "")
        return ("gap: below confidence floor", "gap")

    def hidden(self, cid):
        return '<input type="hidden" name="t" value="%s"><input type="hidden" name="clause" value="%s">' % (
            esc(self.token), esc(cid))

    def button(self, cid, action, label):
        return '<form method="post" action="/decide">%s<input type="hidden" name="action" value="%s">' \
               '<button type="submit">%s</button></form>' % (self.hidden(cid), action, esc(label))

    def doc_select(self, selected):
        docs = self.sess["docs"]
        if len(docs) == 1:
            return '<input type="hidden" name="doc" value="0">'
        opts = "".join('<option value="%d"%s>%s</option>' % (i, " selected" if i == selected else "", esc(d["name"]))
                       for i, d in enumerate(docs))
        return '<label>document <select name="doc">%s</select></label>' % opts

    def render_row(self, row):
        cid = row["clause_id"]
        label, cls = self.state(row)
        d = self.sess["decisions"].get(cid)
        ex = d["excerpt"] if d and d["action"] == "edit" else row.get("excerpt")
        parts = ['<div class="row" id="c-%s"><span class="cid">%s</span> %s<span class="badge %s">%s</span>'
                 % (esc(cid), esc(cid), esc(row["clause_title"]), cls, esc(label))]
        if row.get("clause_text"):
            parts.append("<details><summary>clause text</summary><blockquote>%s</blockquote></details>"
                         % esc(row["clause_text"]))
        if ex:
            parts.append('<blockquote>%s</blockquote><div class="loc">%s &middot; confidence %s</div>' % (
                esc(ex["text"]), esc(ex["location_text"]),
                esc(row["confidence"]) if not (d and d["action"] == "edit") else "n/a (reviewer span)"))
        else:
            parts.append('<div class="loc">no candidate excerpt in these documents</div>')
        if row.get("excerpt"):
            parts.append(self.button(cid, "confirm", "Confirm"))
        parts.append(self.button(cid, "not_covered", "Not covered"))
        if d:
            parts.append(self.button(cid, "reset", "Reset"))
        cur = ex["doc"] if ex else 0
        parts.append('<details><summary>Edit span (must be the document\'s exact words)</summary>'
                     '<form method="post" action="/decide">%s<input type="hidden" name="action" value="edit">%s'
                     '<textarea name="span">%s</textarea><button type="submit">Save span</button></form>'
                     % (self.hidden(cid), self.doc_select(cur), esc(ex["text"] if ex else "")))
        alts = row.get("candidates", [])[1:]
        if alts:
            parts.append("<div class='loc'>other candidates:</div>")
            for c in alts:
                doc = self.sess["docs"][c["doc"]]
                ch = doc["chunks"][c["chunk"] - 1]
                parts.append('<blockquote>%s</blockquote><div class="loc">%s &middot; confidence %s</div>'
                             '<form method="post" action="/decide">%s<input type="hidden" name="action" value="edit">'
                             '<input type="hidden" name="doc" value="%d"><input type="hidden" name="span" value="%s">'
                             '<button type="submit">Use this span</button></form>'
                             % (esc(ch["text"]), esc(il.location_text(doc, ch)), esc(c["confidence"]),
                                self.hidden(cid), c["doc"], esc(ch["text"])))
        parts.append("</details></div>")
        return "".join(parts)

    def page(self, error=None):
        fw = self.sess["fw"]
        rows = sorted(self.sess["rows"], key=lambda r: (r["status"] != "proposed", -r["confidence"], r["clause_id"]))
        n_dec = len(self.sess["decisions"])
        body = ['<h1>Confirm policy mappings: %s %s</h1>' % (esc(fw["id"]), esc(fw.get("version") or "")),
                '<div class="meta">catalog sha256 %s &middot; documents: %s &middot; matcher %s, floor %s &middot; '
                '%d clauses, %d decided</div>' % (
                    esc(fw["catalog_sha256"]), esc(", ".join(d["name"] for d in self.sess["docs"])),
                    esc(self.sess["matcher"]["backend"]), esc(self.sess["floor"]), len(rows), n_dec),
                '<p class="meta">The Collector proposes; you confirm. Only rows you Confirm or Edit are sealed as '
                'confirmed. Not covered becomes a recorded gap. Untouched proposals are sealed as unconfirmed. '
                'Nothing here judges the policy; it records where it says what.</p>']
        if error:
            body.append('<div class="err">%s</div>' % esc(error))
        body.extend(self.render_row(r) for r in rows)
        body.append('<div class="seal"><form method="post" action="/seal"><input type="hidden" name="t" value="%s">'
                    '<label>Reviewer name <input name="reviewer" maxlength="%d" required></label> '
                    '<button type="submit">Seal package</button></form></div>' % (esc(self.token), MAX_REVIEWER))
        return self.wrap("".join(body))

    def sealed_page(self):
        s = self.sealed
        return self.wrap('<h1>Sealed</h1><p>package %s</p><p class="meta">package_hash %s &middot; %d confirmed, '
                         '%d unconfirmed, %d gaps. This page is now closed; verify with '
                         '<code>ingestmode.py verify</code>.</p>' % (esc(s["path"]), esc(s["package_hash"]),
                                                                    s["confirmed"], s["unconfirmed"], s["gaps"]))

    @staticmethod
    def wrap(inner):
        return ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
                'content="width=device-width,initial-scale=1"><title>Confirm mappings</title><style>%s</style>'
                '</head><body>%s</body></html>' % (CSS, inner))


def make_handler(review, allowed_hosts):
    class Handler(BaseHTTPRequestHandler):
        server_version = "beacon-confirm"
        sys_version = ""

        def log_message(self, *a):
            pass

        def send(self, code, body, location=None):
            data = body.encode("utf-8")
            self.send_response(code)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "
                             "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def gate(self, token):
            if self.headers.get("Host", "") not in allowed_hosts:
                self.send(403, Review.wrap("<p>wrong host</p>"))
                return False
            if review.done.is_set():
                self.send(410, Review.wrap("<p>this review is sealed and closed</p>"))
                return False
            if not token or not hmac.compare_digest(token.encode(), review.token.encode()):
                self.send(403, Review.wrap("<p>forbidden</p>"))
                return False
            return True

        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            q = urllib.parse.parse_qs(u.query)
            if u.path != "/" or not self.gate((q.get("t") or [""])[0]):
                if u.path != "/":
                    self.send(404, Review.wrap("<p>not found</p>"))
                return
            with review.lock:
                self.send(200, review.page())

        def do_POST(self):
            u = urllib.parse.urlsplit(self.path)
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = -1
            if n < 0 or n > MAX_BODY:
                self.send(413, Review.wrap("<p>request too large</p>"))
                return
            raw = self.rfile.read(n).decode("utf-8", "replace")
            form = {k: v[0] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}
            if not self.gate(form.get("t", "")):
                return
            with review.lock:
                if u.path == "/decide":
                    err = review.decide(form)
                    if err:
                        self.send(400, review.page(error=err))
                    else:
                        self.send(303, "", location="/?t=%s#c-%s" % (review.token, urllib.parse.quote(form["clause"])))
                elif u.path == "/seal":
                    sealed, err = review.seal(form.get("reviewer", ""))
                    if err:
                        self.send(400, review.page(error=err))
                        return
                    self.send(200, review.sealed_page())
                    review.done.set()
                else:
                    self.send(404, Review.wrap("<p>not found</p>"))
    return Handler


def start(sess, seal_fn, port=0):
    """Start the confirm page in a background thread; returns (server, url, review)."""
    review = Review(sess, seal_fn)
    srv = ThreadingHTTPServer(("127.0.0.1", port), None)
    real_port = srv.server_address[1]
    srv.RequestHandlerClass = make_handler(review, {"127.0.0.1:%d" % real_port, "localhost:%d" % real_port})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d/?t=%s" % (real_port, review.token), review


def serve(sess, seal_fn, open_browser=True, port=0):
    srv, url, review = start(sess, seal_fn, port=port)
    print("confirm page (local only, closes when you seal): %s" % url)
    if open_browser:
        webbrowser.open(url)
    try:
        review.done.wait()
    except KeyboardInterrupt:
        print("\nreview abandoned; nothing sealed")
    finally:
        srv.shutdown()
    if review.sealed:
        s = review.sealed
        print("sealed -> %s | package_hash %s | %d confirmed, %d unconfirmed, %d gaps | NO score." % (
            s["path"], s["package_hash"][:16], s["confirmed"], s["unconfirmed"], s["gaps"]))
    return review.sealed
