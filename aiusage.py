#!/usr/bin/env python3
"""
aiusage.py, Beacon Collector: AI service use observed in network logs (export mode).

The shadow-AI question, answered from logs the org already has: which AI services
are people and systems reaching, how much, and since when. Works on DNS, TLS (SNI)
and HTTP/proxy logs from Security Onion (Zeek), any Zeek install, or a proxy or
DNS export as JSON lines or CSV. Matching is a deterministic lookup against a
versioned catalog (`catalogs-ai/ai-services-v0.json`); no generative component.

Minimised on purpose. Network logs are personal data: they say who visited what.
  - Only AI-catalog domains are counted. Every other domain is dropped at parse
    time and never written anywhere.
  - Client addresses are used only to count distinct clients and are never
    written. Services reached by fewer than --suppress-below clients (default 3)
    report "in use" without an exact client count, so a small office cannot read
    one person's habits off the package.
  - The raw logs are NOT retained in the package. Each input is recorded by
    SHA-256, size and line count, so the org can later prove which files fed the
    seal from the copies it keeps; the sealed blob is the minimised summary.
It never sees content (prompts, uploads). It never rates.

What it cannot see, stated in every package:
  DNS over HTTPS and encrypted client hello hide domains from these logs; remote
  and split-tunnel users outside the sensor are invisible; DNS caching
  undercounts; one address is not one person (NAT, DHCP); the catalog is
  indicative, so an unknown AI service is uncounted, not absent.

Usage:
  aiusage.py collect --log dns.log [--log ssl.log ...] --subject NAME [--format auto]
                     [--suppress-below 3] [--sign --home ~/.beacon] [--out-dir out-aiusage]
  aiusage.py verify PACKAGE.json [--registry DIR] [--blobs DIR]
"""
import argparse
import csv
import io
import json
import os
import sys

import beaconlib as bl

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG = os.path.join(HERE, "catalogs-ai", "ai-services-v0.json")
SLOT = "ai-usage:network-observed"
VERSION = "0.1.0"

DOMAIN_FIELDS = ("query", "server_name", "host", "dns.question.name", "dns.query.name",
                 "tls.client.server_name", "ssl.server_name", "url.domain",
                 "destination.domain", "http.virtual_host", "domain", "hostname")
CLIENT_FIELDS = ("id.orig_h", "source.ip", "client.ip", "src_ip", "client", "source_ip")
TIME_FIELDS = ("ts", "@timestamp", "timestamp", "time")
LIMITS = [
    "DNS over HTTPS and encrypted client hello hide domains from DNS and TLS logs",
    "remote and split-tunnel users outside the sensor are not seen",
    "DNS caching undercounts repeat use",
    "one client address is not one person (NAT, DHCP, shared machines)",
    "the catalog is indicative: an AI service missing from it is uncounted, not absent",
    "content (prompts, uploads) is never visible here and never sought",
]


def load_catalog(path=CATALOG):
    with open(path) as f:
        cat = json.load(f)
    index = {}
    for s in cat["services"]:
        for d in s["domains"]:
            index[d.lower().rstrip(".")] = s
    return cat, index


def match(domain, index):
    """Suffix match: 'api.openai.com' and 'x.chatgpt.com' match their entries."""
    d = (domain or "").lower().rstrip(".")
    while d:
        if d in index:
            return index[d]
        if "." not in d:
            return None
        d = d.split(".", 1)[1]
    return None


def _dig(obj, dotted):
    if dotted in obj:
        return obj[dotted]
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _first(obj, fields):
    for f in fields:
        v = _dig(obj, f)
        if isinstance(v, list):
            v = v[0] if v else None
        if v not in (None, "", "-"):
            return str(v)
    return None


def _ts(v):
    """Zeek epoch seconds or ISO 8601, normalised to an ISO string for ordering."""
    if v is None:
        return None
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(float(v), timezone.utc).isoformat()
    except (TypeError, ValueError):
        return str(v)


def rows(text, fmt):
    """Yield dicts from Zeek TSV, JSON lines, or CSV. Bad lines are counted by the caller."""
    if fmt == "auto":
        head = text.lstrip()[:200]
        fmt = "zeek-tsv" if head.startswith("#separator") or head.startswith("#fields") else \
              "ndjson" if head.startswith("{") else "csv"
    if fmt == "zeek-tsv":
        fields, path = None, None
        for line in text.splitlines():
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#path"):
                path = line.split("\t")[1] if "\t" in line else None
            elif line.startswith("#") or not line.strip():
                continue
            elif fields:
                vals = line.split("\t")
                r = dict(zip(fields, vals)) if len(vals) == len(fields) else None
                if r is not None:
                    r["_log"] = path
                yield r
    elif fmt == "ndjson":
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
                yield r if isinstance(r, dict) else None
            except ValueError:
                yield None
    else:
        for r in csv.DictReader(io.StringIO(text)):
            yield {k.strip().lower(): v for k, v in r.items() if k}


def observe(inputs, index, suppress_below):
    services, clients = {}, {}
    totals = {"events_parsed": 0, "events_ai": 0, "lines_unparseable": 0,
              "events_without_domain": 0}
    window = [None, None]
    log_types = set()
    for text, fmt in inputs:
        for r in rows(text, fmt):
            if r is None:
                totals["lines_unparseable"] += 1
                continue
            totals["events_parsed"] += 1
            if r.get("_log"):
                log_types.add(r["_log"])
            domain = _first(r, DOMAIN_FIELDS)
            if not domain:
                totals["events_without_domain"] += 1
                continue
            ts = _ts(_first(r, TIME_FIELDS))
            if ts:
                window[0] = min(window[0], ts) if window[0] else ts
                window[1] = max(window[1], ts) if window[1] else ts
            s = match(domain, index)
            if not s:
                continue  # non-AI domain: dropped here, never stored
            totals["events_ai"] += 1
            k = s["service"]
            e = services.setdefault(k, {"service": k, "vendor": s["vendor"], "kind": s["kind"],
                                        "events": 0, "first_seen": None, "last_seen": None,
                                        "matched_domains": {}})
            e["events"] += 1
            if ts:
                e["first_seen"] = min(e["first_seen"], ts) if e["first_seen"] else ts
                e["last_seen"] = max(e["last_seen"], ts) if e["last_seen"] else ts
            # record which catalog entry matched, not the full hostname (subdomains can
            # carry tenant or user identifiers)
            entry = next(d for d in s["domains"] if domain.lower().rstrip(".").endswith(d))
            e["matched_domains"][entry] = e["matched_domains"].get(entry, 0) + 1
            c = _first(r, CLIENT_FIELDS)
            if c:
                clients.setdefault(k, set()).add(c)
    out = []
    for k, e in sorted(services.items(), key=lambda kv: -kv[1]["events"]):
        n = len(clients.get(k, ()))
        if n >= suppress_below:
            e["distinct_clients"] = n
        else:
            e["distinct_clients"] = None
            e["distinct_clients_note"] = "fewer than %d; exact count suppressed" % suppress_below
        out.append(e)
    return {"ai_service_use": {
        "present": totals["events_parsed"] > 0,
        "services": out,
        "services_count": len(out),
        "by_kind": _by_kind(out),
        "totals": totals,
        "window": {"first": window[0], "last": window[1]},
        "log_types": sorted(log_types),
        "suppress_below": suppress_below,
        "limits": LIMITS,
        "note": "observed from the org's own network logs; org-level counts, no person-level "
                "records; non-AI domains and client addresses are never stored"}}


def _by_kind(services):
    k = {}
    for s in services:
        k[s["kind"]] = k.get(s["kind"], 0) + s["events"]
    return k


def collect(args):
    cat, index = load_catalog(args.catalog)
    inputs, refs = [], []
    for p in args.log:
        if not os.path.exists(p):
            sys.exit("log not found: %s" % p)
        with open(p, "rb") as f:
            raw = f.read()
        refs.append({"name": os.path.basename(p), "sha256": bl.sha256(raw), "bytes": len(raw),
                     "lines": raw.count(b"\n"), "retained": False})
        inputs.append((raw.decode("utf-8", "replace"), args.format))
    obs = observe(inputs, index, args.suppress_below)
    obs["ai_service_use"]["inputs"] = refs
    obs["ai_service_use"]["catalog"] = {"id": cat["catalog"], "updated": cat["updated"],
                                        "sha256": bl.sha256(bl.canonical(cat))}

    now = bl.utcnow()
    os.makedirs(args.out_dir, exist_ok=True)
    blob_dir = os.path.join(args.out_dir, "blobs")
    os.makedirs(blob_dir, exist_ok=True)
    blob = bl.canonical({"schema": "vcri.beacon.ai-usage-summary/0", "observation": obs})
    blob_hash = bl.sha256(blob)
    with open(os.path.join(blob_dir, "sha256-" + blob_hash + ".json"), "wb") as f:
        f.write(blob)

    item = {
        "subcriterion": SLOT, "mode": "export",
        "source": {"tool": "network-logs", "kind": "dns_tls_http_export",
                   "raw_sha256": blob_hash,
                   "raw_note": "the blob is the minimised summary; input logs are referenced "
                               "by hash in the observation and kept by the org, not here"},
        "provenance": {"box": args.box or "network-sensor", "access": "log-export",
                       "source_system": args.source_system},
        "observation": obs,
        "epistemic": "observed_export", "verified_by_collector": True,
        "context": [],
        "completeness": bl.completeness(obs, ["ai_service_use"]),
        "freshness": {"collected_utc": now, "evidence_age_seconds": 0,
                      "note": "covers the log window stated in the observation, not the present"},
        "artifact_ref": "blob/sha256-" + blob_hash, "collected_utc": now,
    }
    subject = {"name": args.subject or "unknown", "scope": "network-observed-ai-use",
               "collected_utc": now}
    collector = {"name": "beacon-aiusage", "version": VERSION, "platform": "any"}
    core = bl.build_package(subject, collector, [item])
    try:
        package = bl.seal_and_sign(core, sign=args.sign, home=args.home)
    except RuntimeError as e:
        sys.exit(str(e))
    out_path = os.path.join(args.out_dir, "package.json")
    with open(out_path, "w") as f:
        f.write(json.dumps(package, indent=2))

    a = obs["ai_service_use"]
    print("AI service use from %d log file(s): %d events parsed, %d to AI services, %d services"
          % (len(refs), a["totals"]["events_parsed"], a["totals"]["events_ai"], a["services_count"]))
    for s in a["services"]:
        print("  %-20s %-8s %6d events  clients %s" % (
            s["service"], s["kind"], s["events"],
            s["distinct_clients"] if s["distinct_clients"] is not None
            else "<%d" % args.suppress_below))
    print("  window %s to %s; epistemic=observed_export; NO score" % (a["window"]["first"], a["window"]["last"]))
    print("  package_hash: %s -> %s" % (package["seal"]["package_hash"][:16], out_path))


def verify(args):
    with open(args.package) as f:
        pkg = json.load(f)
    blob_dir = args.blobs or os.path.join(os.path.dirname(os.path.abspath(args.package)), "blobs")
    sys.exit(0 if bl.verify_package(pkg, blob_dir=blob_dir, registry=args.registry) else 1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--log", action="append", required=True)
    c.add_argument("--format", choices=["auto", "zeek-tsv", "ndjson", "csv"], default="auto")
    c.add_argument("--catalog", default=CATALOG)
    c.add_argument("--suppress-below", type=int, default=3)
    c.add_argument("--subject")
    c.add_argument("--box")
    c.add_argument("--source-system", default="network-logs")
    c.add_argument("--sign", action="store_true")
    c.add_argument("--home", default=os.path.expanduser("~/.beacon"))
    c.add_argument("--out-dir", default="out-aiusage")
    v = sub.add_parser("verify")
    v.add_argument("package")
    v.add_argument("--registry")
    v.add_argument("--blobs")
    a = ap.parse_args()
    (collect if a.cmd == "collect" else verify)(a)
