"""Diff and timeline for sealed agent-mode evidence packages.

Three levels, each independently verifiable against the sealed record:

  surface  -> which watched surface digests moved (already in chain.changed_surfaces)
  element  -> which of the 17 elements changed (item_sha256 comparison)
  field    -> what inside the observation changed (JSON Pointer paths)

Two consumers, deliberately:

  humans   -> text renderer and a self-contained HTML change ribbon
  machines -> the diff document itself, a stable schema where every change event
              carries the from/to item hashes so a third party can re-derive it
              from the packages without trusting this tool

Nothing here mutates evidence. Read-only by construction.
"""

import base64
import datetime
import glob
import html
import json
import os

SCHEMA = "beacon-agent-diff/v0.1"

# ---------------------------------------------------------------- loading


def load_packages(state_dir):
    """Every sealed package on disk, ordered by chain sequence.

    Reads the packages directory directly rather than the seal log: the log is
    an index, not an authority, and a diff that trusted it would inherit its
    editability.
    """
    pattern = os.path.join(os.path.expanduser(state_dir), "packages", "*", "package.json")
    packages = []
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path) as f:
                pkg = json.load(f)
        except (OSError, ValueError) as e:
            packages.append({"_path": path, "_load_error": type(e).__name__})
            continue
        pkg["_path"] = path
        packages.append(pkg)
    packages.sort(key=lambda p: p.get("chain", {}).get("sequence", 0))
    return packages


def by_sequence(packages):
    return {p.get("chain", {}).get("sequence"): p for p in packages if "chain" in p}


def items_by_slot(pkg):
    return {i["subcriterion"]: i for i in pkg.get("items", [])}


# ---------------------------------------------------------------- field diff


def _pointer(parts):
    """RFC 6901 JSON Pointer from path components."""
    out = ""
    for p in parts:
        out += "/" + str(p).replace("~", "~0").replace("/", "~1")
    return out


def field_changes(old, new, path=None, out=None, max_changes=200):
    """Deep diff of two observation trees into add/remove/replace operations.

    Paths are JSON Pointers so the output is machine-consumable without a
    bespoke parser. Values are included because observations are metadata by
    design (hashes, versions, counts), never content.
    """
    path = path or []
    out = out if out is not None else []
    if len(out) >= max_changes:
        return out

    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted(set(old) | set(new)):
            if key not in new:
                out.append({"op": "remove", "path": _pointer(path + [key]), "from": old[key]})
            elif key not in old:
                out.append({"op": "add", "path": _pointer(path + [key]), "to": new[key]})
            else:
                field_changes(old[key], new[key], path + [key], out, max_changes)
        return out

    if isinstance(old, list) and isinstance(new, list):
        # Lists here are inventories (endpoints, servers, jobs). Compare as a set
        # of canonical members so reordering is not reported as change.
        old_map = {json.dumps(v, sort_keys=True): v for v in old}
        new_map = {json.dumps(v, sort_keys=True): v for v in new}
        for k in sorted(set(old_map) - set(new_map)):
            out.append({"op": "remove", "path": _pointer(path + ["-"]), "from": old_map[k]})
        for k in sorted(set(new_map) - set(old_map)):
            out.append({"op": "add", "path": _pointer(path + ["-"]), "to": new_map[k]})
        return out

    if old != new:
        out.append({"op": "replace", "path": _pointer(path), "from": old, "to": new})
    return out


# ---------------------------------------------------------------- package diff


# Fields that move on every seal by definition; reporting them as change would
# bury the real signal. They remain in the sealed record, they are just not
# treated as findings.
NOISE_PREFIXES = ("/freshness", "/collected_utc", "/source/raw_sha256", "/artifact_ref")


def diff_packages(old_pkg, new_pkg, include_noise=False):
    old_items = items_by_slot(old_pkg)
    new_items = items_by_slot(new_pkg)

    changed, unchanged = [], []
    for slot in sorted(set(old_items) | set(new_items)):
        a, b = old_items.get(slot), new_items.get(slot)
        if a is None or b is None:
            changed.append({
                "subcriterion": slot,
                "element": (b or a).get("element"),
                "layer": (b or a).get("layer"),
                "element_status": "added" if a is None else "removed",
                "from_item_sha256": a.get("item_sha256") if a else None,
                "to_item_sha256": b.get("item_sha256") if b else None,
                "field_changes": [],
            })
            continue

        if a.get("item_sha256") == b.get("item_sha256"):
            unchanged.append(slot)
            continue

        fields = field_changes(a.get("observation"), b.get("observation"))
        completeness = field_changes(a.get("completeness"), b.get("completeness"))
        for c in completeness:
            c["path"] = "/completeness" + c["path"]
        fields += completeness

        if not include_noise:
            fields = [f for f in fields if not f["path"].startswith(NOISE_PREFIXES)]

        if not fields:
            # Hash moved but only on per-seal bookkeeping. Recorded honestly as a
            # hash-only delta rather than silently dropped or falsely alarming.
            changed.append({
                "subcriterion": slot,
                "element": b.get("element"),
                "layer": b.get("layer"),
                "element_status": "hash-only-delta",
                "from_item_sha256": a.get("item_sha256"),
                "to_item_sha256": b.get("item_sha256"),
                "field_changes": [],
                "note": "item hash moved on per-seal bookkeeping only (timestamps/blob ref)",
            })
            continue

        changed.append({
            "subcriterion": slot,
            "element": b.get("element"),
            "layer": b.get("layer"),
            "element_status": "changed",
            "from_item_sha256": a.get("item_sha256"),
            "to_item_sha256": b.get("item_sha256"),
            "field_changes": fields,
        })

    old_chain = old_pkg.get("chain", {})
    new_chain = new_pkg.get("chain", {})
    linked = new_chain.get("prev_package_hash") == old_pkg.get("seal", {}).get("package_hash")

    return {
        "schema": SCHEMA,
        "from": _endpoint(old_pkg),
        "to": _endpoint(new_pkg),
        "adjacent": new_chain.get("sequence") == old_chain.get("sequence", 0) + 1,
        "directly_chain_linked": linked,
        "seal_reason": new_chain.get("reason"),
        "changed_surfaces": new_chain.get("changed_surfaces", []),
        "changed_files": surface_file_changes(old_pkg, new_pkg),
        "changed_elements": [c for c in changed if c["element_status"] != "hash-only-delta"],
        "hash_only_deltas": [c["subcriterion"] for c in changed
                             if c["element_status"] == "hash-only-delta"],
        "unchanged_elements": unchanged,
    }


def load_blob(pkg):
    """The sealed raw manifest for a package, or None.

    The blob carries per-file hashes for every watched surface. It is sealed
    (its sha256 is inside each item's source.raw_sha256, which is inside the
    signed package hash), so resolving a surface change down to the individual
    file that moved does not step outside the evidence.
    """
    path = pkg.get("_path")
    if not path:
        return None
    raw_hash = None
    for it in pkg.get("items", []):
        raw_hash = it.get("source", {}).get("raw_sha256")
        if raw_hash:
            break
    if not raw_hash:
        return None
    blob = os.path.join(os.path.dirname(path), "blobs", "sha256-" + raw_hash + ".json")
    try:
        with open(blob) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def surface_file_changes(old_pkg, new_pkg):
    """Per-file hash movement inside every changed surface.

    This is the level an investigator actually asks about. "The ssh-surface
    digest moved" is a fact about our manifest; "~/.ssh/config went from hash A
    to hash B at 02:59" is a fact about their machine.
    """
    old_blob, new_blob = load_blob(old_pkg), load_blob(new_pkg)
    if not old_blob or not new_blob:
        return []
    old_s = old_blob.get("surfaces", {})
    new_s = new_blob.get("surfaces", {})
    out = []
    for surface in sorted(set(old_s) | set(new_s)):
        a = (old_s.get(surface) or {}).get("files", {})
        b = (new_s.get(surface) or {}).get("files", {})
        if a == b:
            continue
        changes = []
        for path in sorted(set(a) | set(b)):
            if path not in b:
                changes.append({"file": path, "status": "removed", "from_sha256": a[path]})
            elif path not in a:
                changes.append({"file": path, "status": "added", "to_sha256": b[path]})
            elif a[path] != b[path]:
                changes.append({"file": path, "status": "modified",
                                "from_sha256": a[path], "to_sha256": b[path]})
        if changes:
            out.append({"surface": surface, "files": changes})
    return out


def _endpoint(pkg):
    return {
        "sequence": pkg.get("chain", {}).get("sequence"),
        "package_hash": pkg.get("seal", {}).get("package_hash"),
        "collected_utc": pkg.get("subject", {}).get("collected_utc"),
        "signed": pkg.get("seal", {}).get("signature", {}).get("alg") == "ed25519"
        if isinstance(pkg.get("seal", {}).get("signature"), dict) else None,
        "anchor": pkg.get("seal", {}).get("anchor"),
        "path": pkg.get("_path"),
    }


# ---------------------------------------------------------------- timeline


def build_timeline(packages, include_noise=False):
    """Every consecutive-pair diff across the whole chain, plus seal cadence.

    The cadence numbers are part of the evidence story, not decoration: the gap
    between seals bounds how precisely any change can be located in time, and
    that bound is what an examiner is entitled to know.
    """
    events, gaps = [], []
    prev = None
    for pkg in packages:
        if "_load_error" in pkg:
            continue
        if prev is not None:
            d = diff_packages(prev, pkg, include_noise=include_noise)
            events.append(d)
            t0, t1 = _epoch(prev), _epoch(pkg)
            if t0 and t1:
                gaps.append({"from_sequence": d["from"]["sequence"],
                             "to_sequence": d["to"]["sequence"],
                             "seconds": round(t1 - t0, 1)})
        prev = pkg

    reasons = {}
    for pkg in packages:
        r = pkg.get("chain", {}).get("reason", "unknown")
        reasons[r] = reasons.get(r, 0) + 1

    gap_seconds = [g["seconds"] for g in gaps]
    return {
        "schema": SCHEMA,
        "package_count": len([p for p in packages if "_load_error" not in p]),
        "load_errors": [p["_path"] for p in packages if "_load_error" in p],
        "first": _endpoint(packages[0]) if packages else None,
        "last": _endpoint(packages[-1]) if packages else None,
        "seal_reasons": reasons,
        "cadence": {
            "gaps_observed": len(gap_seconds),
            "max_gap_seconds": max(gap_seconds) if gap_seconds else None,
            "min_gap_seconds": min(gap_seconds) if gap_seconds else None,
            "mean_gap_seconds": round(sum(gap_seconds) / len(gap_seconds), 1) if gap_seconds else None,
            "note": "the largest gap is the blind window: any change made and reverted "
                    "inside one gap never sealed, and this bound is disclosed, never implied away",
        },
        "gaps": gaps,
        "events": events,
    }


def _epoch(pkg):
    ts = pkg.get("subject", {}).get("collected_utc")
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


# ---------------------------------------------------------------- text render


def render_text(doc):
    lines = []
    if doc.get("events") is not None:
        lines.append("BEACON AGENT TIMELINE")
        lines.append("  packages: %s" % doc["package_count"])
        lines.append("  reasons:  %s" % ", ".join("%s=%d" % kv for kv in sorted(doc["seal_reasons"].items())))
        c = doc["cadence"]
        if c["max_gap_seconds"]:
            lines.append("  cadence:  max gap %.1fh, mean %.1fh (blind window = max gap)"
                         % (c["max_gap_seconds"] / 3600.0, c["mean_gap_seconds"] / 3600.0))
        if doc["load_errors"]:
            lines.append("  UNREADABLE PACKAGES: %d" % len(doc["load_errors"]))
        lines.append("")
        for ev in doc["events"]:
            if not ev["changed_elements"]:
                continue
            lines += _render_event(ev)
        return "\n".join(lines)
    return "\n".join(_render_event(doc))


def _render_event(ev):
    lines = ["seq %s -> %s  (%s)  %s" % (
        ev["from"]["sequence"], ev["to"]["sequence"], ev["seal_reason"],
        ev["to"]["collected_utc"] or "")]
    if not ev["directly_chain_linked"]:
        lines.append("  ! not directly chain-linked (non-adjacent or chain break)")
    if ev["changed_surfaces"]:
        lines.append("  surfaces: %s" % ", ".join(ev["changed_surfaces"]))
    for sf in ev.get("changed_files", []):
        for f in sf["files"]:
            if f["status"] == "modified":
                lines.append("    %s  %s: %s -> %s"
                             % (sf["surface"], f["file"], f["from_sha256"][:12], f["to_sha256"][:12]))
            elif f["status"] == "added":
                lines.append("    %s  %s: ADDED %s" % (sf["surface"], f["file"], f["to_sha256"][:12]))
            else:
                lines.append("    %s  %s: REMOVED (was %s)"
                             % (sf["surface"], f["file"], f["from_sha256"][:12]))
    for c in ev["changed_elements"]:
        lines.append("  [%s] %s (%s)" % (c["subcriterion"], c["element"], c["element_status"]))
        for f in c["field_changes"][:12]:
            if f["op"] == "replace":
                lines.append("      ~ %s: %s -> %s" % (f["path"], _short(f["from"]), _short(f["to"])))
            elif f["op"] == "add":
                lines.append("      + %s: %s" % (f["path"], _short(f["to"])))
            else:
                lines.append("      - %s: %s" % (f["path"], _short(f["from"])))
        if len(c["field_changes"]) > 12:
            lines.append("      ... %d more field changes" % (len(c["field_changes"]) - 12))
    lines.append("")
    return lines


def _short(v, n=68):
    s = v if isinstance(v, str) else json.dumps(v, sort_keys=True)
    return s if len(s) <= n else s[:n - 3] + "..."


# ---------------------------------------------------------------- html render


def render_html(doc, packages, title="Agent Evidence Timeline"):
    """Self-contained change ribbon: elements down, seals across, changes lit.

    Deliberately readable at a glance by someone who has never seen the schema,
    because the first audience for a change map is a person deciding whether
    something happened, not a parser.
    """
    slots = []
    for pkg in packages:
        for it in pkg.get("items", []):
            if it["subcriterion"] not in [s[0] for s in slots]:
                slots.append((it["subcriterion"], it["element"], it["layer"]))
    slots.sort(key=lambda s: s[0])

    seqs = [e["to"]["sequence"] for e in doc["events"]]
    changed_at = {}
    for ev in doc["events"]:
        for c in ev["changed_elements"]:
            changed_at.setdefault(c["subcriterion"], {})[ev["to"]["sequence"]] = c

    layer_of = {}
    for slot, element, layer in slots:
        layer_of.setdefault(layer, []).append((slot, element))

    head_cells = "".join(
        '<th class="seqh" title="seal %s">%s</th>' % (s, s) for s in seqs)

    rows = []
    for layer, entries in layer_of.items():
        rows.append('<tr class="layer"><td colspan="%d">%s</td></tr>'
                    % (len(seqs) + 1, html.escape(layer)))
        for slot, element in entries:
            cells = []
            for s in seqs:
                c = changed_at.get(slot, {}).get(s)
                if c is None:
                    cells.append('<td class="cell"></td>')
                else:
                    n = len(c["field_changes"])
                    detail = _cell_detail(c)
                    cells.append(
                        '<td class="cell hit" data-d="%s" title="%s: %d field change(s)">%s</td>'
                        % (html.escape(detail, quote=True), html.escape(slot), n, n or "&#9679;"))
            rows.append('<tr><th class="el"><span class="slot">%s</span>%s</th>%s</tr>'
                        % (html.escape(slot), html.escape(element), "".join(cells)))

    events_html = []
    for ev in doc["events"]:
        if not ev["changed_elements"]:
            continue
        body = []
        for c in ev["changed_elements"]:
            fields = "".join(
                '<li><code>%s</code> %s</li>' % (
                    html.escape(f["path"]),
                    html.escape(("%s &rarr; %s" % (_short(f.get("from")), _short(f.get("to"))))
                                if f["op"] == "replace" else
                                ("added " + _short(f.get("to"))) if f["op"] == "add" else
                                ("removed " + _short(f.get("from")))))
                for f in c["field_changes"][:20])
            body.append(
                '<div class="ev-el"><div class="ev-el-h"><span class="slot">%s</span>%s'
                '<span class="st %s">%s</span></div><ul>%s</ul>'
                '<div class="hashes">%s &rarr; %s</div></div>'
                % (html.escape(c["subcriterion"]), html.escape(c["element"] or ""),
                   html.escape(c["element_status"]), html.escape(c["element_status"]),
                   fields or "<li>no field-level detail</li>",
                   html.escape((c["from_item_sha256"] or "")[:12]),
                   html.escape((c["to_item_sha256"] or "")[:12])))
        files_html = ""
        rows_f = []
        for sf in ev.get("changed_files", []):
            for f in sf["files"]:
                if f["status"] == "modified":
                    what = "%s &rarr; %s" % (html.escape(f["from_sha256"][:12]),
                                             html.escape(f["to_sha256"][:12]))
                elif f["status"] == "added":
                    what = "added, %s" % html.escape(f["to_sha256"][:12])
                else:
                    what = "removed, was %s" % html.escape(f["from_sha256"][:12])
                rows_f.append('<li><code>%s</code> <span class="fh">%s</span></li>'
                              % (html.escape(f["file"]), what))
        if rows_f:
            files_html = ('<div class="files"><div class="files-h">files that moved</div>'
                          '<ul>%s</ul></div>' % "".join(rows_f))

        events_html.append(
            '<section class="ev"><h3>seq %s &rarr; %s <span class="reason">%s</span></h3>'
            '<div class="meta">%s &middot; package %s%s</div>%s%s</section>'
            % (ev["from"]["sequence"], ev["to"]["sequence"],
               html.escape(ev["seal_reason"] or ""),
               html.escape(ev["to"]["collected_utc"] or ""),
               html.escape((ev["to"]["package_hash"] or "")[:16]),
               "" if ev["directly_chain_linked"] else
               ' &middot; <span class="warn">not directly chain-linked</span>',
               files_html, "".join(body)))

    c = doc["cadence"]
    cadence_line = ("max gap %.1fh &middot; mean %.1fh &middot; the max gap is the blind window"
                    % (c["max_gap_seconds"] / 3600.0, c["mean_gap_seconds"] / 3600.0)) \
        if c["max_gap_seconds"] else "single package, no cadence yet"

    return _HTML.replace("{{TITLE}}", html.escape(title)) \
                .replace("{{SUMMARY}}", "%d sealed packages &middot; %s &middot; %s" % (
                    doc["package_count"],
                    ", ".join("%s=%d" % kv for kv in sorted(doc["seal_reasons"].items())),
                    cadence_line)) \
                .replace("{{HEAD}}", head_cells) \
                .replace("{{ROWS}}", "".join(rows)) \
                .replace("{{EVENTS}}", "".join(events_html) or "<p>No element changes recorded.</p>")


def _cell_detail(c):
    bits = ["%s (%s)" % (c["element"], c["element_status"])]
    for f in c["field_changes"][:6]:
        if f["op"] == "replace":
            bits.append("%s: %s -> %s" % (f["path"], _short(f.get("from"), 30), _short(f.get("to"), 30)))
        else:
            bits.append("%s %s" % (f["op"], f["path"]))
    return "\n".join(bits)


_HTML = """<title>{{TITLE}}</title>
<style>
:root{--bg:#fbfbfa;--fg:#1a1a19;--dim:#6b6b68;--line:#e3e3df;--card:#fff;
      --hit:#b45309;--hitbg:#fef3c7;--warn:#b91c1c;--accent:#1e40af;}
:root:not([data-theme="light"]){}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#16161a;--fg:#e8e8e6;--dim:#9a9a96;--line:#2e2e34;--card:#1d1d22;
  --hit:#fbbf24;--hitbg:#3a2c0a;--warn:#f87171;--accent:#93c5fd;}}
:root[data-theme="dark"]{--bg:#16161a;--fg:#e8e8e6;--dim:#9a9a96;--line:#2e2e34;
  --card:#1d1d22;--hit:#fbbf24;--hitbg:#3a2c0a;--warn:#f87171;--accent:#93c5fd;}
body{background:var(--bg);color:var(--fg);font:15px/1.55 ui-sans-serif,-apple-system,
  "Segoe UI",Roboto,sans-serif;margin:0;padding:32px 24px 64px;}
.wrap{max-width:1100px;margin:0 auto;}
h1{font-size:22px;margin:0 0 4px;letter-spacing:-.01em;}
.sub{color:var(--dim);font-size:13px;margin-bottom:28px;}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);
   margin:36px 0 12px;font-weight:600;}
.ribbon{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--card);}
table{border-collapse:collapse;font-size:12px;width:100%;}
th.el{text-align:left;font-weight:500;padding:5px 12px;white-space:nowrap;
  position:sticky;left:0;background:var(--card);border-right:1px solid var(--line);}
.slot{display:inline-block;min-width:52px;color:var(--dim);font-family:ui-monospace,monospace;}
th.seqh{font-weight:500;color:var(--dim);font-family:ui-monospace,monospace;
  padding:6px 0;font-size:11px;min-width:26px;}
tr.layer td{padding:8px 12px 3px;color:var(--dim);font-size:10.5px;
  text-transform:uppercase;letter-spacing:.09em;}
td.cell{border-top:1px solid var(--line);height:22px;text-align:center;min-width:26px;}
td.hit{background:var(--hitbg);color:var(--hit);font-weight:600;cursor:help;
  font-family:ui-monospace,monospace;font-size:11px;}
.ev{border:1px solid var(--line);border-radius:8px;background:var(--card);
  padding:14px 16px;margin-bottom:10px;}
.ev h3{margin:0;font-size:14px;font-family:ui-monospace,monospace;font-weight:600;}
.reason{color:var(--accent);font-weight:500;}
.meta{color:var(--dim);font-size:11.5px;font-family:ui-monospace,monospace;margin:2px 0 10px;}
.warn{color:var(--warn);font-weight:600;}
.ev-el{border-left:2px solid var(--line);padding:2px 0 2px 12px;margin:10px 0;}
.ev-el-h{font-size:13px;font-weight:500;}
.st{margin-left:8px;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;
  color:var(--dim);font-weight:600;}
.ev-el ul{margin:6px 0 4px;padding-left:18px;}
.ev-el li{font-size:12.5px;color:var(--fg);margin:2px 0;}
code{font-family:ui-monospace,monospace;font-size:11.5px;color:var(--accent);}
.hashes{color:var(--dim);font-size:11px;font-family:ui-monospace,monospace;}
.files{background:var(--hitbg);border-radius:6px;padding:8px 12px;margin:8px 0 4px;}
.files-h{font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;color:var(--hit);
  font-weight:700;margin-bottom:4px;}
.files ul{margin:0;padding-left:16px;}
.files li{font-size:12px;margin:2px 0;}
.fh{color:var(--dim);font-family:ui-monospace,monospace;font-size:11px;}
.note{color:var(--dim);font-size:12px;margin-top:28px;border-top:1px solid var(--line);
  padding-top:12px;}
</style>
<div class="wrap">
<h1>{{TITLE}}</h1>
<div class="sub">{{SUMMARY}}</div>
<h2>Change ribbon</h2>
<div class="ribbon"><table>
<tr><th class="el"></th>{{HEAD}}</tr>
{{ROWS}}
</table></div>
<h2>Change events</h2>
{{EVENTS}}
<p class="note">Each cell is a sealed observation, not an interpretation. A lit cell means
that element's item hash moved between those two sealed packages; the count is the number of
field-level changes inside it. Absence of a lit cell means no change was observed between
seals, which is not the same as no change having occurred: anything made and reverted inside
one seal gap never sealed. The largest gap above is that blind window.</p>
</div>
"""
