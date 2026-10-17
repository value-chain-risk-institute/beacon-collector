#!/usr/bin/env python3
"""results.py, Beacon Collector: the one-page results view of a sealed evidence package.

Verifies the package, scores it with the open reference scorer (score.py), and writes
ONE self-contained HTML file you open in any browser: verified or refused, the package
fingerprint, the grade and scores per rubric, the evidence behind every number, the
contradictions, and the gaps. No external fonts, scripts, or requests, so it opens the
same on an air-gapped machine and can be attached to an email as is.

  results.py PACKAGE.json [--out results.html] [--rubrics DIR] [--map MAP.json]
                          [--registry DIR] [--blobs DIR]

A package that does not verify gets a results page that says REFUSED and shows no score.
Beta scores use the DRAFT evidence map and the page says so.
"""
import argparse
import contextlib
import html
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import beaconlib as bl
import score as sc

HERE = os.path.dirname(os.path.abspath(__file__))
VCRI = "The Value Chain Risk Institute"
TAGLINE = "Inside data, not guesses."
VCRI_URL = "https://valuechainrisk.org"

CSS = """
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
background:#f6f7f9;color:#14171f;line-height:1.5}main{max-width:960px;margin:0 auto;padding:28px 16px 48px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:30px 0 10px}h3{font-size:15px;margin:18px 0 6px}
.sub{color:#5b6475;margin:0 0 18px}.card{background:#fff;border:1px solid #dfe3ea;border-radius:10px;padding:16px 18px;margin:12px 0}
.badge{display:inline-block;font-weight:700;font-size:12px;letter-spacing:.05em;text-transform:uppercase;padding:3px 10px;border-radius:999px}
.ok{background:#e3f6ec;color:#11683d}.bad{background:#fde8e8;color:#9b1c1c}.warn{background:#fff4d6;color:#7a5200}
.kv{display:grid;grid-template-columns:170px 1fr;gap:4px 14px;font-size:14px}.kv b{color:#5b6475;font-weight:600}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;word-break:break-all}
.grade{font-size:44px;font-weight:800;line-height:1}.score-row{display:flex;gap:28px;align-items:center;flex-wrap:wrap}
.metric{font-size:13px;color:#5b6475}.metric span{display:block;font-size:20px;font-weight:700;color:#14171f}
.bar{display:grid;grid-template-columns:minmax(120px,220px) 1fr 96px;gap:10px;align-items:center;margin:6px 0;font-size:14px}
.track{background:#edf0f4;border-radius:5px;height:12px;overflow:hidden}.fill{height:100%;background:#2f6fde}.dim{color:#8a93a3}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #edf0f4;vertical-align:top}
th{color:#5b6475;font-weight:600;font-size:12.5px}.lvl{font-weight:700}.cls{font-size:12px;color:#5b6475}
.note{font-size:13px;color:#5b6475}footer{margin-top:36px;padding-top:14px;border-top:1px solid #dfe3ea;font-size:13px;color:#5b6475}
@media print{body{background:#fff}.card{break-inside:avoid}}
"""


def e(x):
    return html.escape("" if x is None else str(x))


def verify(pkg, pkg_path, blobs, registry):
    blob_dir = blobs or os.path.join(os.path.dirname(os.path.abspath(pkg_path)), "blobs")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ok = bl.verify_package(pkg, blob_dir=blob_dir, registry=registry)
    return ok, buf.getvalue().strip()


def header_html(pkg, ok, vlog):
    seal = pkg.get("seal", {}) or {}
    subj = pkg.get("subject", {}) or {}
    col = pkg.get("collector", {}) or {}
    sig = seal.get("signature")
    anchor = seal.get("anchor")
    anchor_state = anchor.get("state") if isinstance(anchor, dict) else (anchor or "none")
    times = sorted(i.get("collected_utc") for i in pkg.get("items", []) if i.get("collected_utc"))
    h = ['<div class="card">',
         '<p><span class="badge %s">%s</span></p>' % ("ok" if ok else "bad",
                                                    "Package verified" if ok else "Refused: package does not verify"),
         '<div class="kv">',
         "<b>Subject</b><span>%s</span>" % e(subj.get("name")),
         "<b>Scope</b><span>%s</span>" % e(subj.get("scope") or "not stated"),
         "<b>Collected</b><span>%s</span>" % (e(times[0] + " to " + times[-1]) if times else "not stated"),
         "<b>Evidence items</b><span>%d</span>" % len(pkg.get("items", [])),
         "<b>Package fingerprint</b><span class=\"mono\">%s</span>" % e(seal.get("package_hash")),
         "<b>Hash algorithm</b><span>%s</span>" % e(seal.get("alg") or "sha256"),
         "<b>Signature</b><span>%s</span>" % ("signed" if sig else "unsigned (declared)"),
         "<b>Independent timestamp</b><span>%s</span>" % e(anchor_state),
         "<b>Collector</b><span>%s</span>" % e(" ".join(str(col.get(k, "")) for k in ("name", "version")).strip() or "not stated"),
         "</div>"]
    if not ok:
        h.append('<h3>Why it was refused</h3><pre class="mono">%s</pre>' % e(vlog))
        h.append('<p class="note">A package that fails verification has been changed since it was sealed, or is incomplete. '
                 'It is not scored. Re-collect, or find the original.</p>')
    h.append("</div>")
    return "\n".join(h)


def rubric_html(rid, r):
    pct = round(100 * r["coverage_fraction"])
    h = ['<div class="card">', "<h3>%s</h3>" % e(r.get("title") or rid),
         '<div class="score-row">',
         '<div><div class="grade">%s</div><div class="metric">grade, on the evidence present</div></div>' % e(r["grade_covered"] or "n/a"),
         '<div class="metric">Score on covered areas<span>%s / %s</span></div>' % (e(r["score_covered"]), e(r["scaleMax"])),
         '<div class="metric">Coverage<span>%d of %d (%d%%)</span></div>' % (r["subcriteria_scored"], r["subcriteria_total"], pct),
         '<div class="metric">Comparable score<span>%s / %s</span></div>' % (e(r["score_comparable"]), e(r["scaleMax"])),
         "</div>",
         '<p class="note">The grade uses only the areas your evidence covers. The comparable score counts every '
         'uncovered area as zero, so it rises as you add evidence. Low coverage is not a bad posture; it is missing evidence.</p>',
         "<h3>By area</h3>"]
    mx = float(r.get("scaleMax", 5)) or 5.0
    for d in r["dimensions"]:
        v = d["score_covered"]
        if v is None:
            h.append('<div class="bar"><span>%s</span><span class="track"></span><span class="dim">no evidence</span></div>' % e(d["name"]))
        else:
            h.append('<div class="bar"><span>%s</span><span class="track"><span class="fill" style="display:block;width:%d%%"></span></span><span>%.2f</span></div>'
                     % (e(d["name"]), round(100 * v / mx), v))
    rows = []
    for d in r["dimensions"]:
        for s in d["subcriteria"]:
            if s["level"] is None:
                continue
            ev = s["evidence"] or {}
            rows.append("<tr><td>%s</td><td>%s</td><td class=\"lvl\">%s</td><td><span class=\"cls\">%s, capped at %s</span></td><td>%s</td><td class=\"mono\">%s</td></tr>"
                        % (e(s["key"]), e(s["title"]), e(s["level"]), e(ev.get("class")), e(ev.get("cap")), e(ev.get("why")),
                           e((ev.get("item_sha256") or "")[:16])))
    if rows:
        h.append("<h3>The evidence behind each number</h3><table><tr><th>Item</th><th>What it measures</th><th>Level</th>"
                 "<th>Evidence class</th><th>Why</th><th>Item hash</th></tr>%s</table>" % "".join(rows))
    h.append("</div>")
    return "\n".join(h)


def page(pkg, pkg_path, ok, vlog, out):
    title = "Beacon results: %s" % ((pkg.get("subject") or {}).get("name") or "evidence package")
    body = ["<main>", "<h1>%s</h1>" % e(title),
            '<p class="sub">Open reference score from the Beacon Collector. %s</p>' % e(TAGLINE),
            "<h2>Evidence package</h2>", header_html(pkg, ok, vlog)]
    if ok and out is not None:
        status = out.get("map_status") or "draft"
        body.append('<p><span class="badge warn">Draft method</span> <span class="note">Levels are proposals until VCRI ratifies '
                    'the evidence map. Level 5 is never awarded by this scorer. Map status: %s</span></p>' % e(status))
        body.append("<h2>Scores</h2>")
        if not out["rubrics"]:
            body.append('<div class="card"><p>No scorable evidence in this package yet.</p></div>')
        for rid, r in out["rubrics"].items():
            body.append(rubric_html(rid, r))
        if out["contradictions"]:
            body.append("<h2>Contradictions</h2><div class=\"card\"><p class=\"note\">Where stronger evidence and a claim disagree, "
                        "the stronger evidence wins and the disagreement is shown, not averaged away.</p><table>"
                        "<tr><th>Area</th><th>What was observed</th><th>What was claimed</th></tr>")
            for c in out["contradictions"]:
                body.append("<tr><td>%s / %s</td><td>level %s: %s</td><td>level %s: %s</td></tr>" % (
                    e(c["rubric"]), e(c["key"]), e(c["observed"]["level"]), e(c["observed"]["why"]),
                    e(c["attested"]["raw_level"]), e(c["attested"]["why"])))
            body.append("</table></div>")
        if out["gaps"]:
            body.append("<h2>Gaps</h2><div class=\"card\"><p class=\"note\">Evidence the rubric has no place for yet. "
                        "This is a methodology question for VCRI, not a problem with your evidence.</p><table>"
                        "<tr><th>Evidence slot</th><th>Reason</th></tr>")
            for g in out["gaps"]:
                body.append("<tr><td class=\"mono\">%s</td><td>%s</td></tr>" % (e(g["slot"]), e(g["reason"])))
            body.append("</table></div>")
    body.append("<h2>Check it yourself</h2><div class=\"card\"><p class=\"note\">Anyone holding the package can confirm this page. "
                "Run <code>python3 score.py %s</code> from the open Beacon Collector and compare the package fingerprint and scores "
                "with the ones above. Change one byte of the package and it will no longer verify.</p></div>" % e(os.path.basename(pkg_path)))
    body.append("<footer>Beacon Collector results by %s. %s <a href=\"%s\">%s</a>. A results page is a position on the evidence, not a "
                "certification.</footer></main>" % (e(VCRI), e(TAGLINE), VCRI_URL, VCRI_URL.replace("https://", "")))
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>%s</title><style>%s</style></head><body>%s</body></html>\n" % (e(title), CSS, "\n".join(body)))


def main(argv=None):
    ap = argparse.ArgumentParser(description="One-page HTML results for a sealed Beacon evidence package.")
    ap.add_argument("package")
    ap.add_argument("--out", help="output HTML (default: results.html beside the package)")
    ap.add_argument("--rubrics", default=os.path.join(HERE, "rubrics"))
    ap.add_argument("--map", default=os.path.join(HERE, "scorer-evidence-map-v0.json"))
    ap.add_argument("--registry")
    ap.add_argument("--blobs")
    a = ap.parse_args(argv)

    pkg = sc.load(a.package)
    ok, vlog = verify(pkg, a.package, a.blobs, a.registry)
    out = None
    if ok:
        emap = sc.load(a.map)
        ids = sc.load(os.path.join(a.rubrics, "index.json"))
        rubrics = {rid: sc.load(os.path.join(a.rubrics, rid + ".json")) for rid in ids
                   if os.path.isfile(os.path.join(a.rubrics, rid + ".json"))}
        out = sc.score_package(pkg, rubrics, emap)
    dest = a.out or os.path.join(os.path.dirname(os.path.abspath(a.package)), "results.html")
    with open(dest, "w") as f:
        f.write(page(pkg, a.package, ok, vlog, out))
    print("%s: %s -> %s" % ("VERIFIED" if ok else "REFUSED", a.package, dest))
    print("package fingerprint: %s" % (pkg.get("seal", {}) or {}).get("package_hash"))
    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()
