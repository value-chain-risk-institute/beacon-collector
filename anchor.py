#!/usr/bin/env python3
"""anchor.py, Beacon Collector: anchor, upgrade and verify one sealed package.

  anchor.py stamp   PACKAGE.json [--home ~/.beacon] [--no-ots]
  anchor.py upgrade PACKAGE.json        # pull the Bitcoin path into <pkg>.ots
  anchor.py verify  PACKAGE.json        # offline, the way a third party would

Every org mode (collector, docs, exportmode, merge) anchors at write time
unless --no-anchor was given; this CLI is for retrying, upgrading and checking.
Files beside the package: <pkg>.tsr (RFC 3161 token), <pkg>.ots (OpenTimestamps
proof), <pkg>.anchors.json (the honest record of what was and was not obtained).
"""
import argparse
import json
import os
import sys

import anchors as an


def stamp(a):
    pkg = an._load_json(a.package) or {}
    sealed = (pkg.get("subject") or {}).get("collected_utc")
    rec = an.anchor_package(a.package, sealed_utc=sealed, home=a.home, do_ots=not a.no_ots)
    for x in rec.get("anchors", []):
        extra = x.get("substate") or x.get("reason") or x.get("error") or ""
        print("%-14s %s%s" % (x.get("kind"), x.get("state"), (" (%s)" % extra[:100]) if extra else ""))


def upgrade(a):
    ok, rec = an.upgrade_package_anchors(a.package)
    if rec is None:
        sys.exit("no anchor record for %s" % a.package)
    for x in rec.get("anchors", []):
        if x.get("kind") == "opentimestamps":
            print("opentimestamps %s%s" % (x.get("state"),
                  (" block %s" % x.get("bitcoin_block")) if x.get("bitcoin_block") else ""))
    sys.exit(0 if ok else 2)


def verify(a):
    ok, findings = an.verify_package_anchors(a.package)
    for kind, msg in findings:
        print("%-14s %s" % (kind, msg))
    print("ANCHORS %s" % ("OK" if ok else "PROBLEM"))
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("stamp"); s.add_argument("package"); s.add_argument("--home", default=os.path.expanduser("~/.beacon")); s.add_argument("--no-ots", action="store_true")
    u = sub.add_parser("upgrade"); u.add_argument("package")
    v = sub.add_parser("verify"); v.add_argument("package")
    a = ap.parse_args()
    {"stamp": stamp, "upgrade": upgrade, "verify": verify}[a.cmd](a)


if __name__ == "__main__":
    main()
