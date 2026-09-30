#!/usr/bin/env python3
"""Tests for the 2026-09-30 adapters: sbommode, scorecardmode, outsidein, exportcsv, oscalmode.

Run: python test_adapters.py      (offline; no credentials, no network)

Fixtures in samples/adapters/ are synthetic, written by hand for this suite; no real
organization, person, tenant, repository or system is described. Claims under test:
  - each adapter reads its fixture into the facts the fixture actually contains;
  - every item carries an `epistemic` label from the house vocabulary, and a slot id
    that is either in the scorer evidence map or the reserved value "unmapped";
  - no observation carries a grade, level, rating or roll-up score (invariant 1);
  - every package goes through beaconlib's seal and verifies, and a one-field edit, an
    edited raw blob, and a re-signed forgery are each refused;
  - the scorer reads the packages, and unmapped evidence is reported as a gap.
"""
import base64
import contextlib
import copy
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

import adapterkit as ak
import beaconlib as bl
import exportcsv
import oscalmode
import outsidein
import sbommode
import score as sc
import scorecardmode

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "samples", "adapters")
EPISTEMIC = {"observed_scan", "observed_export", "third_party_attestation", "subject_claim"}
FORBIDDEN = {"grade", "level", "rating", "posture", "score"}
fails = []


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def quiet_verify(pkg, blob_dir=None):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        return bl.verify_package(pkg, blob_dir=blob_dir)


def keys_deep(o):
    if isinstance(o, dict):
        for k, v in o.items():
            yield k
            yield from keys_deep(v)
    elif isinstance(o, list):
        for v in o:
            yield from keys_deep(v)


def run(script, *args):
    r = subprocess.run([sys.executable, os.path.join(HERE, script)] + list(args),
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def house_rules(label, pkg, emap):
    items = pkg["items"]
    check("%s: every item has a house epistemic label" % label,
          all(it.get("epistemic") in EPISTEMIC for it in items))
    check("%s: every slot is in the evidence map or is 'unmapped'" % label,
          all(it["subcriterion"] in emap["slots"] or it["subcriterion"] == ak.UNMAPPED for it in items))
    check("%s: unmapped items say why" % label,
          all(it["mapping"]["status"] == "unmapped" and it["mapping"]["reason"]
              for it in items if it["subcriterion"] == ak.UNMAPPED))
    check("%s: no grade/level/rating/score key in any observation" % label,
          not (FORBIDDEN & set(keys_deep([it["observation"] for it in items]))))


def cli_roundtrip(label, script, args, emap, rubrics):
    """collect via the real CLI, verify, then three forgeries that must fail."""
    tmp = tempfile.mkdtemp(prefix="beacon-adapter-")
    out = os.path.join(tmp, "out")
    rc, log = run(script, "collect", *args, "--subject", "synthetic", "--out-dir", out, "--no-anchor")
    check("%s: collect exits 0" % label, rc == 0)
    pkg_path = os.path.join(out, "package.json")
    pkg = json.load(open(pkg_path))
    house_rules(label, pkg, emap)
    rc, log = run(script, "verify", pkg_path)
    check("%s: verify passes on the untouched package" % label, rc == 0 and "VALID" in log)
    check("%s: anchor state honestly 'unanchored' under --no-anchor" % label,
          pkg["seal"]["anchor"]["state"] == "unanchored")

    t = copy.deepcopy(pkg)
    obs = t["items"][0]["observation"]
    k = sorted(obs)[0]
    obs[k] = {"present": True, "tampered": True} if isinstance(obs[k], dict) else "tampered"
    json.dump(t, open(pkg_path, "w"))
    rc, log = run(script, "verify", pkg_path)
    check("%s: an edited observation FAILS verify" % label, rc == 1 and "TAMPERED" in log)

    json.dump(pkg, open(pkg_path, "w"))
    blob = os.path.join(out, "blobs", "sha256-" + pkg["items"][0]["source"]["raw_sha256"] + ".json")
    orig = open(blob, "rb").read()
    open(blob, "wb").write(orig + b" ")
    rc, log = run(script, "verify", pkg_path)
    check("%s: an edited raw artifact FAILS verify" % label, rc == 1 and "TAMPERED blob" in log)
    open(blob, "wb").write(orig)

    out_sc = sc.score_package(pkg, rubrics, emap)
    if any(it["subcriterion"] == ak.UNMAPPED for it in pkg["items"]):
        check("%s: unmapped evidence is a reported gap in the scorer" % label,
              any(g["slot"] == ak.UNMAPPED for g in out_sc["gaps"]))
    shutil.rmtree(tmp)
    return pkg, out_sc


def signed_forgery(label, pkg):
    """Sign with an ephemeral key (never the enrolled one), then forge."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    priv = Ed25519PrivateKey.generate()
    pub = base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw,
                                                          serialization.PublicFormat.Raw)).decode()

    def sign(p):
        p["seal"]["signature"] = {"alg": "ed25519", "collector_id": "test", "key_fingerprint": "t",
                                  "public_key_ed25519_b64": pub, "signs": "seal.header_sha256",
                                  "sig_b64": base64.b64encode(priv.sign(p["seal"]["header_sha256"].encode())).decode()}
        return p
    good = sign(bl.seal_and_sign({k: v for k, v in copy.deepcopy(pkg).items() if k != "seal"}, False, "/nonexistent"))
    check("%s: signed package verifies" % label, quiet_verify(good))
    forged = copy.deepcopy(good)
    was = forged["items"][0]["epistemic"]
    forged["items"][0]["epistemic"] = "observed_scan" if was == "observed_export" else "observed_export"
    forged["items"][0]["item_sha256"] = bl.hash_item(forged["items"][0])
    core = {k: v for k, v in forged.items() if k != "seal"}
    resealed = bl.seal_and_sign(core, False, "/nonexistent")
    resealed["seal"]["signature"] = good["seal"]["signature"]
    check("%s: relabeling the evidence class and re-sealing under the old signature FAILS" % label,
          not quiet_verify(resealed))


def main():
    emap = json.load(open(os.path.join(HERE, "scorer-evidence-map-v0.json")))
    ids = json.load(open(os.path.join(HERE, "rubrics", "index.json")))
    rubrics = {rid: json.load(open(os.path.join(HERE, "rubrics", rid + ".json"))) for rid in ids}

    print("SBOM ingestion (CycloneDX, SPDX)")
    obs, meta = sbommode.observe(json.load(open(os.path.join(FIX, "cyclonedx-sample.json"))))
    inv = obs["package_inventory"]
    check("CycloneDX: nested components counted (4)", inv["count"] == 4)
    check("CycloneDX: purl/hash/license/supplier counts 3/1/2/1",
          (inv["with_purl"], inv["with_hash"], inv["with_license"], inv["with_supplier"]) == (3, 1, 2, 1))
    check("CycloneDX: ecosystems from purl types", inv["ecosystems"] == ["npm", "pypi"])
    check("CycloneDX 1.5 tools object read", meta["tools"] == ["syft"])
    obs, meta = sbommode.observe(json.load(open(os.path.join(FIX, "spdx-sample.json"))))
    inv = obs["package_inventory"]
    check("SPDX: 3 packages, NOASSERTION is not a license or supplier",
          (inv["count"], inv["with_license"], inv["with_supplier"]) == (3, 2, 1))
    check("SPDX: creator tools parsed", meta["tools"] == ["trivy-0.56.0"])
    check("signature never claimed", obs["signed_attestation"]["present"] is False)
    try:
        sbommode.observe({"not": "an sbom"})
        check("non-SBOM JSON refused", False)
    except ValueError:
        check("non-SBOM JSON refused", True)
    for f in ("cyclonedx-sample.json", "spdx-sample.json"):
        pkg, out = cli_roundtrip("sbom " + f, "sbommode.py", ["--sbom", os.path.join(FIX, f)], emap, rubrics)
        check("sbom %s: Stated class, collector did not verify contents" % f,
              pkg["items"][0]["epistemic"] == "subject_claim" and pkg["items"][0]["verified_by_collector"] is False)
        lvl = out["rubrics"]["technology-v1"]["dimensions"][0]["subcriteria"][0]["level"]
        check("sbom %s: scorer caps a declared SBOM at the Stated ceiling (1)" % f, lvl == 1)
        check("sbom %s: evidence age from the SBOM's own timestamp" % f,
              pkg["items"][0]["freshness"]["evidence_age_seconds"] > 0)
    signed_forgery("sbom", pkg)

    print("OpenSSF Scorecard")
    result = json.load(open(os.path.join(FIX, "scorecard-sample.json")))
    obs, unm, meta = scorecardmode.observe(result)
    check("checks grouped onto existing slots",
          sorted(obs) == ["process-v1:change-management", "technology-v1:1.1a", "technology-v1:4.4a", "technology-v1:6.6c"])
    check("an inconclusive (-1) check is not 'present'", obs["technology-v1:1.1a"]["present"] is False)
    check("unmapped checks kept, not dropped", sorted(unm) == ["Maintained", "Security-Policy"])
    check("repo normalization", scorecardmode.normalize_repo("https://github.com/ossf/scorecard.git") == "github.com/ossf/scorecard"
          and scorecardmode.normalize_repo("ossf/scorecard") == "github.com/ossf/scorecard")
    pkg, out = cli_roundtrip("scorecard", "scorecardmode.py",
                             ["--repo", "synthetic-org/synthetic-repo", "--file", os.path.join(FIX, "scorecard-sample.json")],
                             emap, rubrics)
    check("scorecard: aggregate roll-up score is not in any item", "6.1" not in json.dumps([i["observation"] for i in pkg["items"]]))
    check("scorecard: labeled third-party automated", all(i["source"]["kind"] == "third_party_automated" for i in pkg["items"]))
    signed_forgery("scorecard", pkg)

    print("outside-in (offline: DNS parser and certificate reader on synthetic bytes)")
    q = outsidein.build_query("example.org", 0x1234)
    check("DNS query: id, one question, TXT/IN", q[:2] == b"\x12\x34" and q[4:6] == b"\x00\x01" and q.endswith(b"\x00\x10\x00\x01"))
    txt1, txt2 = b"v=spf1 include:_spf.example.org ", b"-all"
    rdata = bytes([len(txt1)]) + txt1 + bytes([len(txt2)]) + txt2
    resp = (b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:] +
            b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x01\x2c" + len(rdata).to_bytes(2, "big") + rdata)
    r = outsidein.parse_txt_response(resp, 0x1234)
    check("DNS answer: compressed name skipped, split TXT strings joined", r["txt"] == ["v=spf1 include:_spf.example.org -all"])
    check("DNS NXDOMAIN is an empty answer, not an error",
          outsidein.parse_txt_response(b"\x12\x34\x81\x83" + b"\x00" * 8, 0x1234)["rcode"] == "NXDOMAIN")
    check("SPF facts: all-mechanism qualifier", outsidein.spf_facts(r["txt"])["all_mechanism"] == "-all")
    check("SPF facts: two records counted, not judged", outsidein.spf_facts(["v=spf1 -all", "v=spf1 ~all"])["record_count"] == 2)
    d = outsidein.dmarc_facts(["v=DMARC1; p=reject; sp=quarantine; rua=mailto:x@example.org"])
    check("DMARC facts: p, sp, rua", (d["policy"], d["subdomain_policy"], d["aggregate_reporting"]) == ("reject", "quarantine", True))

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from datetime import timedelta
    k = ec.generate_private_key(ec.SECP256R1())
    now = datetime(2026, 9, 30, tzinfo=timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic.example")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=10)).not_valid_after(now + timedelta(days=45))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("synthetic.example")]), False)
            .sign(k, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    c = outsidein.describe_cert(der, now)
    check("certificate: days until expiry computed at collection time", c["days_until_expiry"] == 45)
    check("certificate: SANs read", c["san_dns_names"] == ["synthetic.example"])

    fake_dns = {"synthetic.example": {"rcode": "NOERROR", "txt": ["v=spf1 -all"], "truncated": False},
                "_dmarc.synthetic.example": {"rcode": "NXDOMAIN", "txt": [], "truncated": False}}
    fake_tls = lambda host: ({"present": True, "host": host, "port": 443, "negotiated_protocol": "TLSv1.3",
                              "chain_valid_and_hostname_match": True, "certificate": c}, der)
    email, tls, raw = outsidein.observe("synthetic.example", lambda n: fake_dns[n], fake_tls)
    check("absent DMARC recorded as absent", email["dmarc"]["present"] is False)
    tmp = tempfile.mkdtemp(prefix="beacon-oi-")
    stamp = bl.utcnow()
    raw_hash = ak.write_blob(tmp, bl.canonical(raw))
    items = outsidein.build_items("synthetic.example", email, tls, raw_hash, stamp, None)
    pkg = bl.seal_and_sign(bl.build_package({"name": "synthetic", "scope": "t", "collected_utc": stamp},
                                            {"name": "test", "version": "0"}, items), False, "/nonexistent")
    house_rules("outside-in", pkg, emap)
    check("outside-in: observed from an external vantage, labeled so",
          all(i["provenance"]["access"] == "external-vantage" and i["epistemic"] == "observed_scan" for i in items))
    check("outside-in: sealed package verifies with its blob", quiet_verify(pkg, tmp + "/blobs"))
    t = copy.deepcopy(pkg)
    t["items"][0]["observation"]["tls"]["certificate"]["days_until_expiry"] = 400
    check("outside-in: a stretched certificate expiry FAILS verify", not quiet_verify(t, tmp + "/blobs"))
    signed_forgery("outside-in", pkg)
    shutil.rmtree(tmp)

    print("CSV exports the org downloads itself")
    rows = exportcsv.read_rows(open(os.path.join(FIX, "entra-registration-sample.csv"), "rb").read())
    o = exportcsv.entra_mfa(rows)
    check("Entra: 2/4 registered, named gaps", o["people-v1:mfa"][1]["coverage_fraction"] == 0.5
          and o["people-v1:mfa"][1]["accounts_without_mfa"] == ["bob@synthetic.example", "svc-backup@synthetic.example"])
    check("Entra: labeled registration, not enforcement", o["people-v1:mfa"][1]["basis"] == "registration")
    check("Entra: admin ratio 2/4", o["people-v1:least-privilege"][1]["privileged_fraction"] == 0.5)
    rows = exportcsv.read_rows(open(os.path.join(FIX, "gworkspace-users-sample.csv"), "rb").read())
    o = exportcsv.gworkspace_users(rows)
    check("Google: 2SV 2/3 active, 1 enforced, suspended excluded from coverage",
          (o["people-v1:mfa"][1]["mfa_enabled"], o["people-v1:mfa"][1]["active_accounts"], o["people-v1:mfa"][1]["enforced"]) == (2, 3, 1))
    check("Google: suspended account still present counted for jml", o["people-v1:jml"][1]["disabled_or_suspended_still_present"] == 1)
    o = exportcsv.training(exportcsv.read_rows(open(os.path.join(FIX, "knowbe4-training-sample.csv"), "rb").read()))
    t = o[ak.UNMAPPED][1]
    check("training: 4 enrollments, 3 users, 2 completed, 2 users with an incomplete enrollment",
          (t["enrollments"], t["users"], t["completed"], len(t["users_with_incomplete_enrollment"])) == (4, 3, 2, 2))
    o = exportcsv.phishing(exportcsv.read_rows(open(os.path.join(FIX, "knowbe4-phishing-sample.csv"), "rb").read()))
    p = o[ak.UNMAPPED][1]
    check("phishing: 3 recipients, 1 clicked, 1 reported, 1 entered data",
          (p["recipients"], p["clicked"], p["reported"], p["data_entered"]) == (3, 1, 1, 1))
    o = exportcsv.aws_iam(exportcsv.read_rows(open(os.path.join(FIX, "aws-iam-credential-report-sample.csv"), "rb").read()),
                          datetime(2026, 9, 30, tzinfo=timezone.utc))
    m, k = o["people-v1:mfa"][1], o["technology-v1:2.2a"][1]
    check("AWS IAM: 1/2 console users with MFA, root MFA on, key-only user excluded",
          (m["mfa_enabled"], m["active_accounts"], m["root_mfa_active"], m["accounts_without_mfa"]) == (1, 2, True, ["bob-synthetic"]))
    check("AWS IAM: 3 active keys, oldest rotated 1003 days ago, 1 over 90 days, 1 never used",
          (k["active_access_keys"], k["oldest_rotation_days"], k["keys_rotated_over_90_days"],
           k["keys_never_used_or_idle_over_90_days"], k["root_access_keys_active"]) == (3, 1003, 1, 1, 0))
    try:
        exportcsv.entra_mfa(exportcsv.read_rows(b"foo,bar\n1,2\n"))
        check("an unrecognized header fails loudly", False)
    except ValueError:
        check("an unrecognized header fails loudly", True)
    for src, f in (("entra-mfa", "entra-registration-sample.csv"), ("gworkspace-users", "gworkspace-users-sample.csv"),
                   ("training", "knowbe4-training-sample.csv"), ("phishing", "knowbe4-phishing-sample.csv"),
                   ("aws-iam-credential-report", "aws-iam-credential-report-sample.csv")):
        pkg, out = cli_roundtrip("csv " + src, "exportcsv.py", ["--csv", os.path.join(FIX, f), "--source", src], emap, rubrics)
    signed_forgery("csv", pkg)
    pkg, out = cli_roundtrip("csv gworkspace (score)", "exportcsv.py",
                             ["--csv", os.path.join(FIX, "gworkspace-users-sample.csv"), "--source", "gworkspace-users"], emap, rubrics)
    lvl = [s for d in out["rubrics"]["people-v1"]["dimensions"] for s in d["subcriteria"] if s["key"] == "2a"][0]["level"]
    check("Google 2SV 0.667 observed -> scorer's existing MFA ladder reads it (level 2)", lvl == 2)

    print("OSCAL JSON (SSP, Assessment Results, POA&M)")
    check("control ids: objective, statement, and parenthesized enhancement forms",
          [oscalmode.control_of(x) for x in ("ia-2.1_obj", "ac-2_smt.j", "AC-2(1)")] == ["ia-2.1", "ac-2", "ac-2.1"])
    check("enhancement falls back to its base control", oscalmode.slots_for("ac-6.1") == ["people-v1:least-privilege"])
    kind, key, epi, obs, meta = oscalmode.observe(json.load(open(os.path.join(FIX, "oscal-ssp-sample.json"))))
    check("SSP: Stated; ia-2.1 -> mfa, ac-2 -> jml, pe-3 unmapped",
          epi == "subject_claim" and sorted(obs) == ["people-v1:jml", "people-v1:mfa", ak.UNMAPPED]
          and obs[ak.UNMAPPED]["source_controls"] == ["pe-3"])
    kind, key, epi, obs, meta = oscalmode.observe(json.load(open(os.path.join(FIX, "oscal-ar-sample.json"))))
    check("AR: Attested; findings routed by target control", epi == "third_party_attestation"
          and sorted(obs) == ["people-v1:jml", "people-v1:mfa", ak.UNMAPPED])
    check("AR: not-satisfied finding carried as such", obs["people-v1:jml"]["not_satisfied"] == 1)
    check("AR: origin actor types and methods kept per finding",
          obs["people-v1:mfa"]["records"][0]["origin_actor_types"] == ["assessment-platform"]
          and obs["people-v1:mfa"]["records"][0]["methods"] == ["EXAMINE", "TEST"])
    check("AR --self-assessed relabels as Stated",
          oscalmode.observe(json.load(open(os.path.join(FIX, "oscal-ar-sample.json"))), True)[2] == "subject_claim")
    kind, key, epi, obs, meta = oscalmode.observe(json.load(open(os.path.join(FIX, "oscal-poam-sample.json"))))
    check("POA&M: open gap routed to jml through its finding; unlinked item unmapped",
          sorted(obs) == ["people-v1:jml", ak.UNMAPPED] and obs["people-v1:jml"]["polarity"] == "open_gap")
    for f in ("oscal-ssp-sample.json", "oscal-ar-sample.json", "oscal-poam-sample.json"):
        pkg, out = cli_roundtrip("oscal " + f, "oscalmode.py", ["--oscal", os.path.join(FIX, f)], emap, rubrics)
    signed_forgery("oscal", pkg)

    print("\n%d checks failed" % len(fails))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
