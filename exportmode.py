#!/usr/bin/env python3
"""
exportmode.py, Beacon Collector 0.6: EXPORT mode (system-of-record pulls).

Proves the People/Process rubric gets OBSERVED facts, not just attestations.
Scanner mode observes hosts; document mode relays an auditor's claims; export
mode ingests a pull from a system of record (IdP, IGA, PAM, ITSM) and reports
what that record actually SAYS about the estate.

First adapter: IdP export (Okta/Entra/Duo shape), the highest-value single pull
in the source map because it carries MFA coverage, account lifecycle, and
privilege facts at once. Maps to:
  people-v1:mfa               MFA coverage across active accounts
  people-v1:least-privilege   privileged-account ratio
  people-v1:jml               joiner-mover-leaver hygiene (disabled-not-removed, stale)

Epistemic weight (the point of export mode): an IdP export is an OBSERVED fact
about the identity system, epistemic="observed_export". That is stronger than a
SOC 2's third_party_attestation for the SAME slot (people-v1:mfa): the auditor
SAYS "MFA enforced"; the export SHOWS 47/50 active accounts actually have it.
The collector still does not SCORE either one; it records both as facts of
different classes and lets the scorer weigh them.

Input: a JSON array of user records. Recognized fields (all optional, best-effort):
  user/email, mfa_enabled(bool), status(active|disabled|suspended),
  privileged(bool) or role, last_login(ISO date).

  exportmode.py collect --export USERS.json --source idp --subject NAME \
        [--box LABEL] [--sign --home ~/.beacon] [--out-dir out-export]
  exportmode.py verify PACKAGE.json [--registry DIR] [--blobs DIR]

Never scores. Reuses beaconlib for identical seal/sign/verify.
"""
import argparse
import json
import os
import sys

import beaconlib as bl


def _is_active(u):
    return str(u.get("status", "active")).lower() == "active"


def observe_idp(users: list) -> dict:
    active = [u for u in users if _is_active(u)]
    n_active = len(active)

    mfa_on = [u for u in active if u.get("mfa_enabled") is True]
    without_mfa = [u.get("user") or u.get("email") or "?"
                   for u in active if u.get("mfa_enabled") is not True]

    def _priv(u):
        if u.get("privileged") is True:
            return True
        role = str(u.get("role", "")).lower()
        return any(k in role for k in ("admin", "owner", "superuser", "root"))
    privileged = [u for u in active if _priv(u)]

    # jml hygiene: accounts disabled but still present (fact), and stale actives.
    disabled_present = [u for u in users if str(u.get("status", "")).lower() in ("disabled", "suspended")]

    mfa = {"present": n_active > 0, "active_accounts": n_active,
           "mfa_enabled": len(mfa_on),
           "coverage_fraction": round(len(mfa_on) / n_active, 3) if n_active else None,
           "accounts_without_mfa": sorted(without_mfa),
           "note": "observed from the IdP export; a coverage fraction is a FACT, not a grade"}
    least_priv = {"present": n_active > 0,
                  "privileged_accounts": len(privileged),
                  "privileged_fraction": round(len(privileged) / n_active, 3) if n_active else None,
                  "note": "privileged-account ratio observed; whether it is 'too many' is the scorer's judgment"}
    jml = {"present": True,
           "total_records": len(users), "active": n_active,
           "disabled_or_suspended_still_present": len(disabled_present),
           "note": "lifecycle hygiene signal; deprovisioning timeliness needs IdP event logs (later)"}
    return {"people-v1:mfa": mfa,
            "people-v1:least-privilege": least_priv,
            "people-v1:jml": jml}


ADAPTERS = {"idp": observe_idp}


def collect(args):
    adapter = ADAPTERS.get(args.source)
    if not adapter:
        sys.exit("unknown --source %r (have: %s)" % (args.source, ", ".join(ADAPTERS)))
    if not os.path.exists(args.export):
        sys.exit("export file not found: %s" % args.export)

    with open(args.export, "rb") as f:
        raw = f.read()
    raw_hash = bl.sha256(raw)
    try:
        records = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.exit("export is not valid JSON: %s" % e)
    if not isinstance(records, list):
        sys.exit("export must be a JSON array of user records")

    now = bl.utcnow()
    os.makedirs(args.out_dir, exist_ok=True)
    blob_dir = os.path.join(args.out_dir, "blobs")
    os.makedirs(blob_dir, exist_ok=True)
    with open(os.path.join(blob_dir, "sha256-" + raw_hash + ".json"), "wb") as f:
        f.write(raw)

    observations = adapter(records)
    provenance = {"box": args.box or ("idp:" + os.path.basename(args.export)),
                  "access": "system-of-record-export",
                  "source_system": args.source}

    items = []
    for slot, obs in observations.items():
        obs_key = slot.split(":")[1]
        item = {
            "subcriterion": slot,
            "mode": "export",
            "source": {"tool": args.source + "-export", "kind": "system_of_record",
                       "raw_sha256": raw_hash,
                       "export_name": os.path.basename(args.export)},
            "provenance": provenance,
            "observation": {obs_key: obs},
            "epistemic": "observed_export",
            "verified_by_collector": True,
            "context": [],
            "completeness": bl.completeness({obs_key: obs}, [obs_key]),
            "freshness": {"collected_utc": now, "evidence_age_seconds": 0,
                          "note": "export reflects IdP state at pull time"},
            "artifact_ref": "blob/sha256-" + raw_hash,
            "collected_utc": now,
        }
        items.append(item)

    subject = {"name": args.subject or "unknown", "scope": "export:" + args.source,
               "collected_utc": now}
    collector = {"name": "beacon-export-collector", "version": "0.6.0", "platform": "any"}
    core = bl.build_package(subject, collector, items)
    try:
        package = bl.seal_and_sign(core, sign=args.sign, home=args.home)
    except RuntimeError as e:
        sys.exit(str(e))

    out_path = os.path.join(args.out_dir, "package.json")
    with open(out_path, "w") as f:
        f.write(json.dumps(package, indent=2))

    mfa = observations["people-v1:mfa"]
    lp = observations["people-v1:least-privilege"]
    print("ingested %s export (%s), sha256 %s..." % (args.source, os.path.basename(args.export), raw_hash[:12]))
    print("  people-v1:mfa            coverage %s (%d/%d active)%s" % (
        mfa["coverage_fraction"], mfa["mfa_enabled"], mfa["active_accounts"],
        ("  without MFA: " + ", ".join(mfa["accounts_without_mfa"])) if mfa["accounts_without_mfa"] else ""))
    print("  people-v1:least-privilege privileged %d/%d (%s)" % (
        lp["privileged_accounts"], mfa["active_accounts"], lp["privileged_fraction"]))
    print("  people-v1:jml            %d disabled/suspended still present" % (
        observations["people-v1:jml"]["disabled_or_suspended_still_present"]))
    print("  epistemic=observed_export (stronger than a SOC2 attestation for the SAME slot)")
    print("  package_hash: %s  |  NO score." % package["seal"]["package_hash"][:16])


def verify(args):
    pkg = json.load(open(args.package))
    blob_dir = args.blobs or os.path.join(os.path.dirname(os.path.abspath(args.package)), "blobs")
    ok = bl.verify_package(pkg, blob_dir=blob_dir, registry=args.registry)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--export", required=True)
    c.add_argument("--source", default="idp")
    c.add_argument("--subject")
    c.add_argument("--box")
    c.add_argument("--sign", action="store_true")
    c.add_argument("--home", default=os.path.expanduser("~/.beacon"))
    c.add_argument("--out-dir", default="out-export")
    v = sub.add_parser("verify")
    v.add_argument("package")
    v.add_argument("--registry")
    v.add_argument("--blobs")
    a = ap.parse_args()
    (collect if a.cmd == "collect" else verify)(a)
