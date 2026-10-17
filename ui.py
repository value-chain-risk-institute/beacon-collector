#!/usr/bin/env python3
"""
ui.py, Beacon Collector local admin console (v0).

A loopback-only web page over the evidence the collector already sealed. It
adds no measurement of its own: every number on every screen comes from the
same functions the CLI calls (beaconlib.verify_package, beacondiff timeline and
ribbon, agentmode state, report.py coverage and bundle). One implementation
per measurement; this file only arranges and escapes.

Screens (v0): Status, Sources, Timeline, Packages (with Verify), Export.

Security posture (plan section 1.6):
  - binds 127.0.0.1 by default; any non-loopback bind is refused unless
    --allow-remote is given, and then a warning is printed
  - per-launch random token in the printed URL, exchanged once for an
    HttpOnly SameSite=Strict cookie; every request needs that cookie
  - Host header must be 127.0.0.1:<port> or localhost:<port> (DNS rebinding)
  - the only state-changing route (export) is POST with a per-session CSRF
    token and an Origin check; no CORS headers at all
  - CSP default-src 'self' with no script at all, X-Frame-Options DENY,
    Referrer-Policy no-referrer
  - no route edits or deletes evidence; export writes a new directory only
  - exits after an inactivity timeout (default 30 minutes)

Usage:
  ui.py serve [--state ~/.beacon/agent] [--home ~/.beacon] [--port 0]
              [--bind 127.0.0.1] [--allow-remote] [--idle-minutes 30]
              [--exports ~/.beacon/exports]
"""
import argparse
import base64
import contextlib
import datetime
import glob
import hashlib
import html
import io
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import urllib.parse
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agentmode as am
import beaconlib as bl
import beacondiff as bd
import report as rp

VERSION = "0.1.0"
H = os.path.expanduser
LOOPBACK = ("127.0.0.1", "::1", "localhost")
DEFAULT_EXPORTS = "~/.beacon/exports"
DEFAULT_IDLE_MINUTES = 30
DEFAULT_WINDOW = 50
PAGE_SIZE = 100
MAX_BODY = 16 * 1024
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

VERIFIED, TAMPERED, UNPROVEN = "verified", "tampered", "unproven"


def esc(v):
    """Every value that reaches HTML goes through here."""
    return html.escape("" if v is None else str(v), quote=True)


class RefusedBind(Exception):
    pass


# ---------------------------------------------------------------- reading evidence
# Read-only helpers. Nothing below opens a file for writing except export().


def _seq_of(name):
    m = re.match(r"^seq(\d+)", name)
    return int(m.group(1)) if m else -1


def package_names(paths):
    """Package directory names, oldest first. Names only, no parsing, so the
    list screen stays cheap on an 800-package chain."""
    try:
        names = os.listdir(paths["packages"])
    except OSError:
        return []
    out = [n for n in names
           if NAME_RE.match(n) and os.path.isfile(os.path.join(paths["packages"], n, "package.json"))]
    out.sort(key=lambda n: (_seq_of(n), n))
    return out


def package_path(paths, name):
    """Resolve a name from a URL to a package.json, or None. The name must be
    one the directory listing actually contains: no path is built from input."""
    if not name or not NAME_RE.match(name) or name not in set(package_names(paths)):
        return None
    return os.path.join(paths["packages"], name, "package.json")


def load_pkg(path):
    with open(path) as f:
        return json.load(f)


_VERIFY_LOCK = threading.Lock()


def verify_state(pkg_path, home):
    """Run beaconlib.verify_package and map its own verdict lines onto exactly
    one of three states. The mapping reads the verdict beaconlib prints:
      REJECT ...        -> tampered
      INCONCLUSIVE ...  -> unproven
      VALID ...         -> verified
    Anything else (an unreadable file, an exception before a verdict) is
    unproven: not known intact and not known tampered. Unproven is never
    folded into either of the other two."""
    buf = io.StringIO()
    ok = None
    error = None
    try:
        pkg = load_pkg(pkg_path)
    except (OSError, ValueError) as e:
        return UNPROVEN, "package.json could not be read or parsed (%s); nothing was verified." % type(e).__name__
    blob_dir = os.path.join(os.path.dirname(pkg_path), "blobs")
    # redirect_stdout is process wide; the lock keeps two verifies from
    # interleaving their findings.
    with _VERIFY_LOCK:
        with contextlib.redirect_stdout(buf):
            try:
                ok = bl.verify_package(pkg, blob_dir=blob_dir,
                                       registry=os.path.join(H(home), "registry-stub"))
            except Exception as e:  # a crash is not a verdict
                error = "%s: %s" % (type(e).__name__, e)
    out = buf.getvalue()
    if error:
        return UNPROVEN, out + "verification stopped before a verdict: %s\n" % error
    lines = out.splitlines()
    if any(l.startswith("REJECT") for l in lines):
        return TAMPERED, out
    if any(l.startswith("INCONCLUSIVE") for l in lines):
        return UNPROVEN, out
    if ok and any(l.startswith("VALID") for l in lines):
        return VERIFIED, out
    return UNPROVEN, out + "no recognised verdict line; treated as unproven\n"


def signing_status(home, latest_pkg):
    """Signing availability WITHOUT touching the keychain.

    agentmode.can_sign() asks the macOS keychain for the passphrase via
    `security find-generic-password -w`, which can raise an interactive
    prompt. The UI must never prompt, so it reports only what it can see:
    the key file, the env passphrase, and whether the newest package was in
    fact signed. When only the keychain could answer, the answer is unknown."""
    key = os.path.isfile(os.path.join(H(home), "identity.key"))
    if not key:
        avail = "unavailable: no identity.key under %s (packages seal unsigned)" % H(home)
    elif os.environ.get("BEACON_PASSPHRASE"):
        avail = "available (BEACON_PASSPHRASE is set in this process)"
    else:
        avail = ("unknown: identity key present; the passphrase lives in the keychain "
                 "and this UI does not query it")
    last = "no package yet"
    if latest_pkg is not None:
        sig = latest_pkg.get("seal", {}).get("signature", {})
        if isinstance(sig, dict) and sig.get("alg") == "ed25519":
            last = "signed, ed25519, collector %s, key fp %s" % (sig.get("collector_id"), sig.get("key_fingerprint"))
        else:
            last = "unsigned"
    return avail, last


def anchor_counts(paths, home):
    """Counts read from files the anchor jobs already wrote. Cheap: a glob and
    one JSON read. Nothing is checked here; offline verification of anchors is
    `agentmode.py verify-anchors`."""
    tsr = len(glob.glob(os.path.join(paths["packages"], "*", "package.json.tsr")))
    q = am.load_json(os.path.join(paths["dir"], "anchors", "queue.json")) or {}
    by = {}
    for ep in (q.get("epochs") or {}).values():
        for a in ep.get("anchors", []):
            k = (a.get("kind", "?"), a.get("state", "?"))
            by[k] = by.get(k, 0) + 1
    rekor_on = os.path.isfile(os.path.join(H(home), "anchor-trust", "REKOR-ENABLED"))
    return {"rfc3161_tokens": tsr, "epochs": len(q.get("epochs") or {}), "by_kind_state": by,
            "rekor_enabled": rekor_on, "queue_present": bool(q)}


def element_rows(pkg):
    """One row per element: every agentmode element slot, in schedule order,
    then any other slot the package carries (H elements and later), sorted.
    An element missing from the package is a row that says so, never a gap."""
    items = {}
    for it in pkg.get("items", []):
        items.setdefault(it.get("subcriterion"), it)
    order = [e[0] for e in am.ELEMENTS]
    extra = sorted(s for s in items if s not in order)
    rows = []
    for slot in order + extra:
        it = items.get(slot)
        if it is None:
            meta = next((e for e in am.ELEMENTS if e[0] == slot), None)
            rows.append({"slot": slot, "layer": meta[1] if meta else "", "element": meta[2] if meta else "",
                         "status": "absent", "fraction": None, "subs": [],
                         "note": "element not present in this package at all"})
            continue
        comp = it.get("completeness") or {}
        expected = comp.get("expected") or []
        obtained = set(comp.get("obtained") or [])
        obs = it.get("observation") or {}
        subs = []
        for key in expected:
            sub = obs.get(key)
            note = ""
            if isinstance(sub, dict):
                note = sub.get("note") or sub.get("reason") or sub.get("error") or ""
            subs.append({"key": key, "present": key in obtained, "note": note})
        err = obs.get("collection_error") if isinstance(obs, dict) else None
        if isinstance(err, dict):
            subs.append({"key": "collection_error", "present": False,
                         "note": "%s: %s" % (err.get("error"), err.get("note"))})
        frac = comp.get("fraction")
        if frac is None:
            status = "unknown"
        elif frac >= 1:
            status = "present"
        elif frac <= 0:
            status = "absent"
        else:
            status = "partial"
        rows.append({"slot": slot, "layer": it.get("layer"), "element": it.get("element"),
                     "status": status, "fraction": frac, "subs": subs,
                     "note": obs.get("note", "") if isinstance(obs, dict) else ""})
    return rows


# ---------------------------------------------------------------- page chrome

CSS = """:root{--bg:#fbfbfa;--fg:#1a1a19;--dim:#6b6b68;--line:#e3e3df;--card:#fff;
  --ok:#166534;--okbg:#dcfce7;--bad:#b91c1c;--badbg:#fee2e2;--unk:#92400e;--unkbg:#fef3c7;
  --accent:#1e40af;}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#16161a;--fg:#e8e8e6;--dim:#9a9a96;--line:#2e2e34;--card:#1d1d22;
  --ok:#86efac;--okbg:#0f2e1a;--bad:#f87171;--badbg:#3a1212;--unk:#fbbf24;--unkbg:#3a2c0a;
  --accent:#93c5fd;}}
:root[data-theme="dark"]{--bg:#16161a;--fg:#e8e8e6;--dim:#9a9a96;--line:#2e2e34;--card:#1d1d22;
  --ok:#86efac;--okbg:#0f2e1a;--bad:#f87171;--badbg:#3a1212;--unk:#fbbf24;--unkbg:#3a2c0a;
  --accent:#93c5fd;}
*{box-sizing:border-box;}
body{background:var(--bg);color:var(--fg);font:15px/1.55 ui-sans-serif,-apple-system,
  "Segoe UI",Roboto,sans-serif;margin:0;padding:24px 16px 64px;}
.wrap{max-width:1100px;margin:0 auto;}
nav{display:flex;flex-wrap:wrap;gap:4px 18px;border-bottom:1px solid var(--line);
  padding-bottom:10px;margin-bottom:20px;font-size:14px;}
nav a{color:var(--dim);text-decoration:none;}
nav a.on{color:var(--fg);font-weight:600;}
nav .brand{color:var(--fg);font-weight:600;margin-right:12px;}
h1{font-size:22px;margin:0 0 4px;letter-spacing:-.01em;}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);
  margin:28px 0 10px;font-weight:600;}
.sub{color:var(--dim);font-size:13px;margin-bottom:20px;}
a{color:var(--accent);}
.card{border:1px solid var(--line);border-radius:8px;background:var(--card);
  padding:4px 0;overflow-x:auto;}
table{border-collapse:collapse;width:100%;font-size:13px;}
th,td{text-align:left;padding:6px 12px;border-top:1px solid var(--line);vertical-align:top;}
tr:first-child th,tr:first-child td{border-top:none;}
th{font-weight:500;color:var(--dim);white-space:nowrap;}
code,.mono{font-family:ui-monospace,monospace;font-size:12px;overflow-wrap:anywhere;}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11.5px;font-weight:600;
  text-transform:uppercase;letter-spacing:.05em;}
.present,.verified{background:var(--okbg);color:var(--ok);}
.absent,.tampered{background:var(--badbg);color:var(--bad);}
.partial,.unproven,.unknown{background:var(--unkbg);color:var(--unk);}
.verdict{border-radius:8px;padding:14px 16px;margin:16px 0;border:1px solid var(--line);}
.verdict .word{font-size:20px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;background:var(--card);
  border:1px solid var(--line);border-radius:6px;padding:10px 12px;}
form{margin:12px 0;display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;}
select,input,button{font:inherit;font-size:14px;padding:4px 8px;max-width:100%;}
button{cursor:pointer;}
.note{color:var(--dim);font-size:12.5px;margin-top:24px;border-top:1px solid var(--line);
  padding-top:10px;}
ul.subs{margin:0;padding-left:16px;}
ul.subs li{margin:2px 0;}
.dim{color:var(--dim);}
"""

NAV = [("/", "Status"), ("/sources", "Sources"), ("/timeline", "Timeline"),
       ("/packages", "Packages"), ("/export", "Export")]


def page(title, body, active="/"):
    nav = "".join('<a href="%s"%s>%s</a>' % (esc(href), ' class="on"' if href == active else "", esc(label))
                  for href, label in NAV)
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>%s</title><link rel=\"stylesheet\" href=\"/static/ui.css\"></head>"
            "<body><div class=\"wrap\"><nav><span class=\"brand\">Beacon Collector</span>%s</nav>"
            "%s</div></body></html>" % (esc(title), nav, body))


def kv_table(rows):
    return '<div class="card"><table>%s</table></div>' % "".join(
        "<tr><th>%s</th><td>%s</td></tr>" % (esc(k), v) for k, v in rows)


def _iso(epoch):
    if not epoch:
        return None
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat(timespec="seconds")


def _hours(seconds):
    return "%.1fh" % (seconds / 3600.0)


# ---------------------------------------------------------------- the app


class App:
    def __init__(self, state, home, exports, idle_seconds):
        self.state_dir = state
        self.home = home
        self.exports = exports
        self.idle_seconds = idle_seconds
        self.paths = am.state_paths(state)
        self.token = secrets.token_urlsafe(32)
        self.sessions = {}            # session id -> csrf token
        self.lock = threading.Lock()
        self.last_activity = time.monotonic()
        self.port = None
        self.allowed_hosts = set()
        self.allowed_origins = set()
        self._cadence_cache = (None, None)

    # ---- auth bookkeeping
    def new_session(self):
        sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[sid] = csrf
        return sid

    def touch(self):
        self.last_activity = time.monotonic()

    @property
    def cookie_name(self):
        # cookies ignore ports, so two consoles on one host would share a name
        return "beacon_ui_%s" % self.port

    # ---- data, all read-only
    def latest(self):
        names = package_names(self.paths)
        if not names:
            return None, None
        name = names[-1]
        try:
            return name, load_pkg(os.path.join(self.paths["packages"], name, "package.json"))
        except (OSError, ValueError):
            return name, None

    def cadence(self):
        """Whole-chain cadence from beacondiff.build_timeline, cached per chain head."""
        names = package_names(self.paths)
        key = (len(names), names[-1] if names else None)
        if self._cadence_cache[0] == key:
            return self._cadence_cache[1]
        pkgs = bd.load_packages(self.state_dir)
        c = bd.build_timeline(pkgs)["cadence"] if pkgs else None
        self._cadence_cache = (key, c)
        return c

    # ---- screens
    def status_page(self):
        state = am.load_state(self.paths)
        name, pkg = self.latest()
        names = package_names(self.paths)
        avail, last_signed = signing_status(self.home, pkg)
        rows = [("state directory", "<code>%s</code>" % esc(self.paths["dir"]))]
        if not state:
            rows.append(("state", "no state.json (collector never ticked)"))
        disk_seq = pkg.get("chain", {}).get("sequence") if pkg else None
        rows += [
            ("sequence", esc(state.get("sequence"))
             + ("" if disk_seq in (None, state.get("sequence")) else
                ' <span class="pill unknown">newest package on disk is seq %s</span>' % esc(disk_seq))),
            ("chain head", "<code>%s</code>" % esc(state.get("last_package_hash"))),
            ("last seal", "%s (%s)" % (esc(state.get("last_seal_utc")), esc(state.get("last_reason")))),
        ]
        last_epoch = state.get("last_seal_epoch")
        if last_epoch:
            due = last_epoch + am.HEARTBEAT_SECONDS
            delta = due - time.time()
            rel = ("in %s" % _hours(delta)) if delta >= 0 else ("overdue by %s" % _hours(-delta))
            rows.append(("heartbeat due", "%s, %s (every %dh)" % (esc(_iso(due)), esc(rel),
                                                                  am.HEARTBEAT_SECONDS // 3600)))
        else:
            rows.append(("heartbeat due", "unknown (no last seal recorded)"))
        rows += [("signing", esc(avail)), ("newest package", esc(last_signed)),
                 ("packages on disk", esc(len(names)))]
        try:
            a = anchor_counts(self.paths, self.home)
            parts = ["RFC 3161 tokens on disk: %d" % a["rfc3161_tokens"], "epochs: %d" % a["epochs"]]
            parts += ["%s %s: %d" % (k, s, n) for (k, s), n in sorted(a["by_kind_state"].items())]
            parts.append("Rekor publication: %s" % ("enabled" if a["rekor_enabled"] else "off (gated)"))
            rows.append(("anchors", "<br>".join(esc(p) for p in parts)))
        except Exception as e:
            rows.append(("anchors", "unknown (%s)" % esc(type(e).__name__)))
        try:
            c = self.cadence()
            if c and c.get("max_gap_seconds"):
                rows.append(("max gap (blind window)",
                             "%s (%s s) over %d gaps; mean %s<br><span class=\"dim\">%s</span>" % (
                                 esc(_hours(c["max_gap_seconds"])), esc(c["max_gap_seconds"]),
                                 c["gaps_observed"], esc(_hours(c["mean_gap_seconds"])), esc(c["note"]))))
            else:
                rows.append(("max gap (blind window)", "no cadence yet (fewer than two packages)"))
        except Exception as e:
            rows.append(("max gap (blind window)", "unknown (%s)" % esc(type(e).__name__)))
        body = ("<h1>Status</h1><div class=\"sub\">Read from the state file and the sealed packages; "
                "nothing on this page is computed by the UI itself.</div>" + kv_table(rows) +
                "<p class=\"note\">Liveness findings (STALE, GAP, EPOCHGAP) are not shown in v0. "
                "Signing is reported without reading the keychain, so it can say unknown.</p>")
        return page("Status", body, "/")

    def sources_page(self):
        name, pkg = self.latest()
        if pkg is None:
            return page("Sources", "<h1>Sources</h1><p>No readable package yet.</p>", "/sources")
        trs = []
        for r in element_rows(pkg):
            subs = "".join(
                '<li><span class="pill %s">%s</span> <code>%s</code>%s</li>' % (
                    "present" if s["present"] else "absent", "present" if s["present"] else "absent",
                    esc(s["key"]), (" " + esc(s["note"])) if s["note"] else "")
                for s in r["subs"])
            frac = "" if r["fraction"] is None else " %d%%" % round(r["fraction"] * 100)
            trs.append("<tr><td class=\"mono\">%s</td><td>%s<div class=\"dim\">%s</div></td>"
                       "<td><span class=\"pill %s\">%s</span>%s</td><td><ul class=\"subs\">%s</ul>%s</td></tr>" % (
                           esc(r["slot"]), esc(r["element"]), esc(r["layer"]), esc(r["status"]),
                           esc(r["status"]), esc(frac), subs,
                           ('<div class="dim">%s</div>' % esc(r["note"])) if r["note"] else ""))
        body = ("<h1>Sources</h1><div class=\"sub\">From the newest package, <a href=\"/package/%s\">%s</a>. "
                "Present or absent is the package's own completeness record. Absent elements are shown, "
                "never hidden.</div><div class=\"card\"><table><tr><th>slot</th><th>element</th>"
                "<th>status</th><th>evidence parts and notes</th></tr>%s</table></div>" % (
                    esc(urllib.parse.quote(name)), esc(name), "".join(trs)))
        return page("Sources", body, "/sources")

    def timeline_html(self, n):
        pkgs = bd.load_packages(self.state_dir)
        if not pkgs:
            return None, 0
        window = pkgs[-n:]
        doc = bd.build_timeline(window)
        out = bd.render_html(doc, window, title="Agent Evidence Timeline (last %d)" % len(window))
        nav = ('<p class="sub"><a href="/">Status</a> &middot; <a href="/sources">Sources</a> &middot; '
               '<a href="/packages">Packages</a> &middot; <a href="/export">Export</a> &middot; window: '
               + " ".join('<a href="/timeline?n=%d">%d</a>' % (k, k) for k in (10, 50, 200, len(pkgs)))
               + ' packages (of %d)</p>' % len(pkgs))
        out = out.replace('<div class="wrap">', '<div class="wrap">' + nav, 1)
        out = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
               '<meta name="viewport" content="width=device-width,initial-scale=1">' + out)
        return out, len(pkgs)

    def packages_page(self, pg):
        names = list(reversed(package_names(self.paths)))
        pages = max(1, (len(names) + PAGE_SIZE - 1) // PAGE_SIZE)
        pg = min(max(1, pg), pages)
        chunk = names[(pg - 1) * PAGE_SIZE: pg * PAGE_SIZE]
        trs = "".join(
            '<tr><td class="mono"><a href="/package/%s">%s</a></td><td>%s</td></tr>' % (
                esc(urllib.parse.quote(n)), esc(n),
                "RFC 3161 token on disk" if os.path.isfile(
                    os.path.join(self.paths["packages"], n, "package.json.tsr")) else
                '<span class="dim">no token file</span>')
            for n in chunk)
        pager = " ".join(('<a href="/packages?page=%d">%d</a>' % (i, i)) if i != pg else "<b>%d</b>" % i
                         for i in range(1, pages + 1))
        body = ("<h1>Packages</h1><div class=\"sub\">%d sealed packages, newest first. Open one to see its "
                "items and verify it.</div><div class=\"card\"><table><tr><th>package</th><th>anchor</th></tr>"
                "%s</table></div><p>%s</p>" % (len(names), trs, pager))
        return page("Packages", body, "/packages")

    def package_page(self, name, do_verify):
        path = package_path(self.paths, name)
        if path is None:
            return None
        try:
            pkg = load_pkg(path)
        except (OSError, ValueError) as e:
            pkg = None
            err = type(e).__name__
        verdict = ""
        if do_verify:
            st, out = verify_state(path, self.home)
            explain = {VERIFIED: "Every item hash, the merkle root, the package hash and the signature (if any) check out.",
                       TAMPERED: "The package was edited after collection. Do not score it.",
                       UNPROVEN: "Not known to be tampered with and not known to be intact. "
                                 "Do not score it until it verifies."}[st]
            verdict = ('<div class="verdict %s"><div class="word">%s</div><div>%s</div></div>'
                       '<h2>verifier output</h2><pre>%s</pre>' % (esc(st), esc(st), esc(explain), esc(out)))
        form = ('<form method="get" action="/package/%s"><input type="hidden" name="verify" value="1">'
                '<button type="submit">Verify</button></form>' % esc(urllib.parse.quote(name)))
        if pkg is None:
            body = "<h1>%s</h1><p>Unreadable package (%s).</p>%s%s" % (esc(name), esc(err), form, verdict)
            return page(name, body, "/packages")
        seal = pkg.get("seal", {}) or {}
        sig = seal.get("signature", {}) or {}
        chain = pkg.get("chain", {}) or {}
        side = [s for s in (".tsr", ".ots", ".anchors.json") if os.path.isfile(path + s)]
        head = kv_table([
            ("subject", esc((pkg.get("subject") or {}).get("name"))),
            ("sequence", esc(chain.get("sequence"))),
            ("reason", esc(chain.get("reason"))),
            ("changed surfaces", esc(", ".join(chain.get("changed_surfaces") or []))),
            ("collected", esc((pkg.get("subject") or {}).get("collected_utc"))),
            ("package hash", "<code>%s</code>" % esc(seal.get("package_hash"))),
            ("previous package hash", "<code>%s</code>" % esc(chain.get("prev_package_hash"))),
            ("merkle root", "<code>%s</code>" % esc(seal.get("merkle_root"))),
            ("signature", esc("%s %s" % (sig.get("alg"), ("fp " + str(sig.get("key_fingerprint")))
                                         if sig.get("alg") == "ed25519" else ""))),
            ("anchor files beside it", esc(", ".join("package.json" + s for s in side) or "none")),
        ])
        trs = []
        for it in pkg.get("items", []):
            grade = rp.item_grade(it)
            comp = it.get("completeness") or {}
            fr = it.get("freshness") or {}
            frac = comp.get("fraction")
            trs.append("<tr><td class=\"mono\">%s</td><td>%s</td><td>%s</td><td>%s/%s%s</td><td>%s<div class=\"dim\">age %s s</div></td>"
                       "<td class=\"mono\">%s</td></tr>" % (
                           esc(it.get("subcriterion")), esc(it.get("element")),
                           esc(rp.CLASS_LABEL.get(grade, grade)),
                           esc(len(comp.get("obtained") or [])), esc(len(comp.get("expected") or [])),
                           "" if frac is None else " (%d%%)" % round(frac * 100),
                           esc(fr.get("collected_utc")), esc(fr.get("evidence_age_seconds")),
                           esc((it.get("item_sha256") or "")[:16])))
        body = ("<h1>%s</h1>%s%s%s<h2>items</h2><div class=\"card\"><table><tr><th>slot</th><th>element</th>"
                "<th>evidence class</th><th>completeness</th><th>freshness</th><th>item hash</th></tr>%s</table></div>"
                "<p class=\"note\">Evidence class is report.item_grade, the same label the coverage report uses. "
                "Verify runs beaconlib.verify_package on this one package; chain linkage across packages is "
                "<code>agentmode.py verify-chain</code>.</p>" % (
                    esc(name), form, verdict, head, "".join(trs)))
        return page(name, body, "/packages")

    def export_page(self, csrf, result=""):
        names = list(reversed(package_names(self.paths)))[:50]
        opts = "".join('<option value="%s">%s</option>' % (esc(n), esc(n)) for n in names)
        fws = "".join('<option value="%s">%s</option>' % (esc(k), esc(v.get("name", k)))
                      for k, v in sorted(rp.FRAMEWORKS.items()))
        body = ("<h1>Export</h1><div class=\"sub\">Builds the report.py evidence bundle (package, blobs, "
                "coverage in md, json and html, README) into a new directory under <code>%s</code>. "
                "The package is verified first and a package that is not verified is refused. Nothing is sent."
                "</div>%s<form method=\"post\" action=\"/export\">"
                "<input type=\"hidden\" name=\"csrf\" value=\"%s\">"
                "<label>package <select name=\"package\">%s</select></label>"
                "<label>overlay <select name=\"framework\">%s</select></label>"
                "<button type=\"submit\">Build bundle</button></form>"
                "<p class=\"note\">v0 exports one package with one overlay. Choosing a window and per-item "
                "disclosure come later.</p>" % (esc(H(self.exports)), result, esc(csrf), opts, fws))
        return page("Export", body, "/export")

    def export(self, name, fw_key):
        """Returns (status, html fragment). Writes only into a directory that
        did not exist a moment ago."""
        path = package_path(self.paths, name)
        if path is None:
            return 400, "<p>Unknown package.</p>"
        if fw_key not in rp.FRAMEWORKS:
            return 400, "<p>Unknown overlay.</p>"
        st, out = verify_state(path, self.home)
        if st != VERIFIED:
            return 409, ('<div class="verdict %s"><div class="word">%s</div><div>Refusing to export: '
                         'the package is not verified.</div></div><pre>%s</pre>' % (esc(st), esc(st), esc(out)))
        root = H(self.exports)
        os.makedirs(root, exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        out_dir = os.path.join(root, stamp)
        os.mkdir(out_dir)  # raises if it exists: never write into an existing directory
        pkg = load_pkg(path)
        fw = rp.FRAMEWORKS[fw_key]
        rows = rp.build(pkg, fw, fw_key)
        rp.write_bundle(pkg, path, fw, rows, out_dir)
        files = sorted(os.path.relpath(os.path.join(d, f), out_dir)
                       for d, _, fs in os.walk(out_dir) for f in fs)
        cov = sum(1 for r in rows if r["coverage"] == "covered")
        return 200, ('<div class="verdict verified"><div class="word">bundle written</div>'
                     '<div><code>%s</code></div><div>%s: %d of %d controls covered (a map, not a '
                     'certification; no score)</div></div><pre>%s</pre>' % (
                         esc(out_dir), esc(fw.get("name", fw_key)), cov, len(rows),
                         esc("\n".join(files))))


# ---------------------------------------------------------------- HTTP


BASE_CSP = ("default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'")


def _style_hash_csp(doc):
    """The ribbon carries one inline <style> block; allow exactly that block by hash."""
    hashes = []
    for m in re.finditer(r"<style>(.*?)</style>", doc, re.S):
        d = base64.b64encode(hashlib.sha256(m.group(1).encode()).digest()).decode()
        hashes.append("'sha256-%s'" % d)
    return BASE_CSP + "; style-src 'self' " + " ".join(hashes)


class Handler(BaseHTTPRequestHandler):
    server_version = "BeaconUI/" + VERSION
    sys_version = ""
    app = None  # set per server

    # ---- plumbing
    def log_message(self, fmt, *args):
        # never log the query string: the launch token travels in it
        path = urllib.parse.urlsplit(getattr(self, "path", "") or "").path
        sys.stderr.write("ui: %s %s %s\n" % (getattr(self, "command", "-"), path,
                                              args[1] if len(args) > 1 else ""))

    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None, csp=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", csp or BASE_CSP)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_error(self, code, message=None, explain=None):
        try:
            self._send(code, "%d %s\n" % (code, message or ""), "text/plain; charset=utf-8")
        except Exception:
            pass

    def _refuse(self, code, why):
        self._send(code, why + "\n", "text/plain; charset=utf-8")

    def _session(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            c = SimpleCookie(raw)
        except CookieError:
            return None
        m = c.get(self.app.cookie_name)
        if m is None:
            return None
        sid = m.value
        with self.app.lock:
            for k in self.app.sessions:
                if secrets.compare_digest(k.encode(), sid.encode("utf-8", "replace")):
                    return k
        return None

    def _gate(self):
        """Host check, token exchange, cookie check. Returns (sid, url) or None
        after having already answered the request."""
        app = self.app
        host = self.headers.get("Host", "")
        if host not in app.allowed_hosts:
            self._refuse(400, "refused: Host header not allowed")
            return None
        url = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(url.query)
        if "token" in q:
            given = q["token"][0]
            if self.command == "GET" and secrets.compare_digest(given.encode("utf-8", "replace"),
                                                                 app.token.encode()):
                sid = app.new_session()
                app.touch()
                rest = [(k, v) for k, vs in q.items() if k != "token" for v in vs]
                loc = url.path + ("?" + urllib.parse.urlencode(rest) if rest else "")
                self._send(303, "", "text/plain", headers={
                    "Location": loc or "/",
                    "Set-Cookie": "%s=%s; HttpOnly; SameSite=Strict; Path=/" % (app.cookie_name, sid)})
                return None
            self._refuse(403, "refused: bad token")
            return None
        sid = self._session()
        if sid is None:
            self._refuse(403, "refused: not authorized; open the launch URL printed in the terminal")
            return None
        app.touch()
        return sid, url

    # ---- methods
    def do_GET(self):
        g = self._gate()
        if g is None:
            return
        sid, url = g
        q = urllib.parse.parse_qs(url.query)
        app = self.app
        path = url.path
        try:
            if path == "/":
                return self._send(200, app.status_page())
            if path == "/static/ui.css":
                return self._send(200, CSS, "text/css; charset=utf-8")
            if path == "/sources":
                return self._send(200, app.sources_page())
            if path == "/timeline":
                try:
                    n = int(q.get("n", [DEFAULT_WINDOW])[0])
                except ValueError:
                    n = DEFAULT_WINDOW
                doc, total = app.timeline_html(max(2, min(n, 100000)))
                if doc is None:
                    return self._send(200, page("Timeline", "<h1>Timeline</h1><p>No packages yet.</p>", "/timeline"))
                return self._send(200, doc, csp=_style_hash_csp(doc))
            if path == "/packages":
                try:
                    pg = int(q.get("page", ["1"])[0])
                except ValueError:
                    pg = 1
                return self._send(200, app.packages_page(pg))
            if path.startswith("/package/"):
                name = urllib.parse.unquote(path[len("/package/"):])
                out = app.package_page(name, q.get("verify", [""])[0] == "1")
                if out is None:
                    return self._send(404, page("Not found", "<h1>No such package</h1>", "/packages"))
                return self._send(200, out)
            if path == "/export":
                return self._send(200, app.export_page(app.sessions[sid]))
            return self._send(404, page("Not found", "<h1>Not found</h1>"))
        except Exception as e:
            return self._send(500, page("Error", "<h1>Error</h1><pre>%s</pre>" % esc("%s: %s" % (type(e).__name__, e))))

    def do_POST(self):
        g = self._gate()
        if g is None:
            return
        sid, url = g
        app = self.app
        origin = self.headers.get("Origin")
        if origin not in app.allowed_origins:
            return self._refuse(403, "refused: cross-origin or missing Origin")
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None and site != "same-origin":
            return self._refuse(403, "refused: cross-site request")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._refuse(400, "refused: bad length")
        if length < 0 or length > MAX_BODY:
            return self._refuse(413, "refused: body too large")
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        csrf = (form.get("csrf") or [""])[0]
        if not secrets.compare_digest(csrf.encode("utf-8", "replace"), app.sessions[sid].encode()):
            return self._refuse(403, "refused: CSRF token mismatch")
        if url.path == "/export":
            try:
                code, frag = app.export((form.get("package") or [""])[0], (form.get("framework") or [""])[0])
            except Exception as e:
                code, frag = 500, "<pre>%s</pre>" % esc("%s: %s" % (type(e).__name__, e))
            return self._send(code, app.export_page(app.sessions[sid], frag))
        return self._send(404, page("Not found", "<h1>Not found</h1>"))


class _Server6(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def make_server(state=am.DEFAULT_STATE, home=am.DEFAULT_HOME, exports=DEFAULT_EXPORTS, port=0,
                bind="127.0.0.1", allow_remote=False, idle_seconds=DEFAULT_IDLE_MINUTES * 60):
    """Build (server, app). Refuses a non-loopback bind unless allow_remote."""
    if bind not in LOOPBACK and not allow_remote:
        raise RefusedBind("refusing to bind %s: the console is loopback only. Use an SSH or "
                          "Tailscale tunnel, or pass --allow-remote if you really mean it." % bind)
    app = App(state, home, exports, idle_seconds)
    handler = type("BoundHandler", (Handler,), {"app": app})
    cls = _Server6 if ":" in bind else ThreadingHTTPServer
    srv = cls((bind, port), handler)
    srv.daemon_threads = True
    app.port = srv.server_address[1]
    hosts = {"127.0.0.1:%d" % app.port, "localhost:%d" % app.port}
    if bind == "::1":
        hosts.add("[::1]:%d" % app.port)
    if bind not in LOOPBACK:
        hosts.add(("[%s]:%d" if ":" in bind else "%s:%d") % (bind, app.port))
    app.allowed_hosts = hosts
    app.allowed_origins = {"http://" + h for h in hosts}
    return srv, app


def launch_url(app):
    return "http://127.0.0.1:%d/?token=%s" % (app.port, app.token)


def start_idle_watch(srv, app):
    def watch():
        while True:
            time.sleep(min(30.0, max(0.2, app.idle_seconds / 4.0)))
            if time.monotonic() - app.last_activity > app.idle_seconds:
                print("ui: idle for %ds, exiting" % app.idle_seconds, flush=True)
                srv.shutdown()
                return
    t = threading.Thread(target=watch, daemon=True)
    t.start()
    return t


def serve(args):
    try:
        srv, app = make_server(args.state, args.home, args.exports, args.port, args.bind,
                               args.allow_remote, int(args.idle_minutes * 60))
    except RefusedBind as e:
        sys.exit(str(e))
    if args.bind not in LOOPBACK:
        print("WARNING: bound to %s, reachable beyond this machine. The token is the only "
              "thing between this console and the network." % args.bind, flush=True)
    print("Beacon UI %s, state %s" % (VERSION, H(args.state)), flush=True)
    print("open: %s" % launch_url(app), flush=True)
    print("exits after %d minutes idle; Ctrl-C to stop now" % args.idle_minutes, flush=True)
    start_idle_watch(srv, app)
    try:
        srv.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


def main():
    ap = argparse.ArgumentParser(description="Beacon Collector local console (loopback only)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--state", default=am.DEFAULT_STATE)
    s.add_argument("--home", default=am.DEFAULT_HOME)
    s.add_argument("--exports", default=DEFAULT_EXPORTS)
    s.add_argument("--port", type=int, default=0, help="0 picks a random free port")
    s.add_argument("--bind", default="127.0.0.1")
    s.add_argument("--allow-remote", action="store_true")
    s.add_argument("--idle-minutes", type=float, default=DEFAULT_IDLE_MINUTES)
    args = ap.parse_args()
    serve(args)


if __name__ == "__main__":
    main()
