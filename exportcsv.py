#!/usr/bin/env python3
"""
exportcsv.py, Beacon Collector export adapters for CSV files the organization
downloads ITSELF from its own admin console. Same pattern as exportmode.py's IdP
adapter (the org pulls, the collector ingests): no API, no credentials, nothing
held by the collector. Items are epistemic="observed_export" (a system of record's
own report of its state) and reuse exportmode's observation keys so the scorer's
existing rules read them.

Sources:
  entra-mfa        Microsoft Entra "User registration details" (Authentication methods
                   activity) CSV. -> people-v1:mfa (REGISTRATION, not enforcement),
                   people-v1:least-privilege (admin flag, when the column exists)
  gworkspace-users Google Workspace Admin console user list CSV (Users > Download).
                   -> people-v1:mfa (2SV enrolled; enforced count kept beside it),
                   people-v1:jml (suspended accounts still present)
  training         KnowBe4-style training campaign CSV -> unmapped (no evidence-map slot)
  phishing         KnowBe4-style phishing test results CSV -> unmapped (no evidence-map slot)

Header matching is by normalized name (case, spaces, punctuation and Google's
"[READ ONLY]" suffixes ignored) against the aliases below. The aliases are written
from vendor documentation and have NOT yet been checked against a real tenant's
download; an unrecognized header fails loudly rather than guessing.

  exportcsv.py collect --csv FILE --source entra-mfa|gworkspace-users|training|phishing [--subject NAME]
  exportcsv.py verify out-exportcsv/package.json
"""
import argparse
import csv
import io
import os
import re
import sys

import adapterkit as ak
import beaconlib as bl


def norm(h):
    return re.sub(r"[^a-z0-9]", "", re.sub(r"\[.*?\]", "", h or "").lower())


def boolish(v):
    s = norm(v)
    if s in ("true", "yes", "1", "y", "enrolled", "enforced", "registered", "capable", "completed", "passed"):
        return True
    if s in ("false", "no", "0", "n", "notenrolled", "notenforced", "notregistered", "", "none"):
        return False
    return None


def col(row_keys, *aliases):
    for a in aliases:
        if a in row_keys:
            return a
    return None


def read_rows(raw):
    text = raw.decode("utf-8-sig", "replace")
    rdr = csv.DictReader(io.StringIO(text))
    return [{norm(k): (v or "").strip() for k, v in r.items() if k is not None} for r in rdr]


def need(keys, name, *aliases):
    c = col(keys, *aliases)
    if c is None:
        raise ValueError("no %s column (looked for %s; have %s)" % (name, ", ".join(aliases), ", ".join(sorted(keys))))
    return c


def entra_mfa(rows):
    keys = set(rows[0]) if rows else set()
    u = need(keys, "user", "userprincipalname", "upn", "user")
    reg = need(keys, "MFA registered", "ismfaregistered", "mfaregistered")
    adm = col(keys, "isadmin", "admin")
    n = len(rows)
    on = [r for r in rows if boolish(r[reg])]
    mfa = {"present": n > 0, "active_accounts": n, "mfa_enabled": len(on),
           "coverage_fraction": round(len(on) / n, 3) if n else None,
           "accounts_without_mfa": sorted(r[u] for r in rows if not boolish(r[reg])),
           "basis": "registration",
           "note": "Entra registration report: MFA REGISTERED, not proof it is enforced at sign-in (that is "
                   "Conditional Access, a Graph adapter); the report does not distinguish disabled accounts"}
    out = {"people-v1:mfa": ("mfa", mfa)}
    if adm:
        p = [r for r in rows if boolish(r[adm])]
        out["people-v1:least-privilege"] = ("least-privilege", {
            "present": n > 0, "privileged_accounts": len(p),
            "privileged_fraction": round(len(p) / n, 3) if n else None,
            "note": "Entra isAdmin flag (holds a directory admin role)"})
    return out


def gworkspace_users(rows):
    keys = set(rows[0]) if rows else set()
    u = need(keys, "email", "emailaddress", "primaryemail", "email")
    st = need(keys, "status", "status", "userstatus")
    enr = need(keys, "2SV enrollment", "2svenrollmentstatus", "2svenrolled", "isenrolledin2sv")
    enf = col(keys, "2svenforcementstatus", "2svenforced", "isenforcedin2sv")
    active = [r for r in rows if norm(r[st]) == "active"]
    susp = [r for r in rows if norm(r[st]) in ("suspended", "archived")]
    on = [r for r in active if boolish(r[enr])]
    n = len(active)
    mfa = {"present": n > 0, "active_accounts": n, "mfa_enabled": len(on),
           "coverage_fraction": round(len(on) / n, 3) if n else None,
           "accounts_without_mfa": sorted(r[u] for r in active if not boolish(r[enr])),
           "enforced": sum(1 for r in active if enf and boolish(r[enf])) if enf else None,
           "basis": "2sv-enrollment",
           "note": "Google 2-Step Verification enrollment across active users; enforcement count kept beside it"}
    jml = {"present": True, "total_records": len(rows), "active": n,
           "disabled_or_suspended_still_present": len(susp),
           "note": "suspended/archived accounts still present in the directory"}
    return {"people-v1:mfa": ("mfa", mfa), "people-v1:jml": ("jml", jml)}


def training(rows):
    keys = set(rows[0]) if rows else set()
    u = need(keys, "user", "email", "emailaddress", "user", "username")
    st = need(keys, "status", "status", "enrollmentstatus", "completionstatus")
    counts = {}
    for r in rows:
        counts[r[st] or "(blank)"] = counts.get(r[st] or "(blank)", 0) + 1
    done = [r for r in rows if norm(r[st]) in ("completed", "passed")]
    done_users = {r[u] for r in done}
    return {ak.UNMAPPED: ("training", {
        "present": bool(rows), "enrollments": len(rows), "users": len({r[u] for r in rows}),
        "completed": len(done), "by_status": dict(sorted(counts.items())),
        "users_with_incomplete_enrollment": sorted({r[u] for r in rows if norm(r[st]) not in ("completed", "passed")})[:200],
        "users_with_no_completion": len({r[u] for r in rows} - done_users)})}


def phishing(rows):
    keys = set(rows[0]) if rows else set()
    u = need(keys, "user", "email", "emailaddress", "user", "username")
    ck = need(keys, "clicked", "clicked", "clickedat", "linkclicked")
    rp = col(keys, "reported", "reportedat")
    de = col(keys, "dataentered", "dataenteredat")
    hit = lambda r, c: bool(c) and (boolish(r[c]) is True or (boolish(r[c]) is None and r[c] != ""))
    return {ak.UNMAPPED: ("phishing_simulation", {
        "present": bool(rows), "recipients": len(rows),
        "clicked": sum(1 for r in rows if hit(r, ck)),
        "reported": sum(1 for r in rows if hit(r, rp)) if rp else None,
        "data_entered": sum(1 for r in rows if hit(r, de)) if de else None,
        "note": "counts from the simulation export; a timestamp in a *At column counts as the event"})}


SOURCES = {"entra-mfa": entra_mfa, "gworkspace-users": gworkspace_users,
           "training": training, "phishing": phishing}
GAP = ("no evidence-map slot for security-awareness training / phishing-simulation results",
       ["people-v1/4b", "people-v1/5b", "people-v1/4c"])


def collect(args):
    fn = SOURCES.get(args.source)
    if not fn:
        sys.exit("unknown --source %r (have: %s)" % (args.source, ", ".join(SOURCES)))
    raw = open(args.csv, "rb").read()
    try:
        obs = fn(read_rows(raw))
    except ValueError as e:
        sys.exit("cannot read %s export: %s" % (args.source, e))
    now = bl.utcnow()
    os.makedirs(args.out_dir, exist_ok=True)
    raw_hash = ak.write_blob(args.out_dir, raw)
    src = {"tool": args.source + "-export", "kind": "system_of_record", "export_name": os.path.basename(args.csv)}
    prov = {"box": args.box or (args.source + ":" + os.path.basename(args.csv)),
            "access": "system-of-record-export", "source_system": args.source}
    fresh = ak.freshness(now, note="the export reflects the console's state when the org downloaded it; "
                                   "the file carries no date of its own")
    items = [ak.make_item(slot, "export", "observed_export", True, src, prov, key, o, raw_hash, now, fresh,
                          ak.unmapped(*GAP) if slot == ak.UNMAPPED else ak.mapped("exportcsv." + args.source))
             for slot, (key, o) in obs.items()]
    subject = {"name": args.subject or "unknown", "scope": "export:" + args.source, "collected_utc": now}
    collector = {"name": "beacon-export-csv", "version": "0.1.0", "platform": "any"}
    package, out_path = ak.seal_write(args, items, subject, collector)
    print("ingested %s CSV (%s), sha256 %s..." % (args.source, os.path.basename(args.csv), raw_hash[:12]))
    ak.summarize(items, package, out_path)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--csv", required=True)
    c.add_argument("--source", required=True, choices=sorted(SOURCES))
    ak.add_common(c, "out-exportcsv")
    ak.add_verify(sub)
    a = ap.parse_args()
    (collect if a.cmd == "collect" else ak.cmd_verify)(a)
