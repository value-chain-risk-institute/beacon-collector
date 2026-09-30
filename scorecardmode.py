#!/usr/bin/env python3
"""
scorecardmode.py, Beacon Collector adapter: OpenSSF Scorecard results for a repo.

Source: the public Scorecard API (api.securityscorecards.dev, no auth, read-only)
or a saved copy of its JSON response (--file, for offline and air-gapped use).

Epistemic class: the collector did not observe the repository; it relays a
result that OpenSSF's automated checks produced. That is a third party's
statement about the subject, so items are epistemic="third_party_attestation",
verified_by_collector=false, with source.kind="third_party_automated" so a
consumer can tell a machine check from an auditor's report. (The schema has no
separate class for third-party automated results; see ADAPTER-ROADMAP.md gaps.)

Invariant 1 (never rate): Scorecard's aggregate 0-10 score is a roll-up; it is
kept only in the sealed raw blob, never in an observation. Per-check results are
relayed verbatim with their reason, labeled as OpenSSF's, not ours.

  scorecardmode.py collect --repo github.com/OWNER/REPO [--file saved.json] [--subject NAME]
  scorecardmode.py verify out-scorecard/package.json
"""
import argparse
import json
import os
import sys
import urllib.request

import adapterkit as ak
import beaconlib as bl

API = "https://api.securityscorecards.dev/projects/"

# Scorecard check -> existing evidence-map slot. Checks not listed are carried in one
# "unmapped" item (with the rubric keys they could live under), never given a new slot.
CHECK_SLOTS = {
    "SAST": "technology-v1:6.6c", "Fuzzing": "technology-v1:6.6c",
    "Token-Permissions": "technology-v1:6.6c", "Dangerous-Workflow": "technology-v1:6.6c",
    "Pinned-Dependencies": "technology-v1:6.6c", "Binary-Artifacts": "technology-v1:6.6c",
    "CI-Tests": "technology-v1:6.6c",
    "Branch-Protection": "process-v1:change-management", "Code-Review": "process-v1:change-management",
    "Vulnerabilities": "technology-v1:4.4a",
    "Signed-Releases": "technology-v1:1.1a", "SBOM": "technology-v1:1.1a",
}
UNMAPPED_CANDIDATES = {
    "Maintained": "technology-v1/1x", "Contributors": "technology-v1/1x",
    "Dependency-Update-Tool": "technology-v1/1c", "Security-Policy": "processes-v1/1a",
    "License": "data-v1/1a", "CII-Best-Practices": "processes-v1/6b",
    "Packaging": "technology-v1/6c", "Webhooks": "technology-v1/6c",
}


def normalize_repo(repo):
    r = repo.strip().rstrip("/")
    for p in ("https://", "http://"):
        if r.startswith(p):
            r = r[len(p):]
    if r.endswith(".git"):
        r = r[:-4]
    if r.count("/") == 1:
        r = "github.com/" + r
    if r.count("/") != 2:
        raise ValueError("repo must look like github.com/OWNER/REPO, got %r" % repo)
    return r


def fetch(repo, timeout=20):
    req = urllib.request.Request(API + repo, headers={"Accept": "application/json",
                                                      "User-Agent": "beacon-collector-scorecard/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def observe(result):
    checks = result.get("checks") or []
    by_slot, unmapped = {}, {}
    for c in checks:
        name = c.get("name")
        rec = {"third_party_check_score_0_10": c.get("score"), "reason": c.get("reason"),
               "inconclusive": c.get("score") == -1}
        slot = CHECK_SLOTS.get(name)
        (by_slot.setdefault(slot, {}) if slot else unmapped)[name] = rec
    obs = {}
    for slot, recs in by_slot.items():
        obs[slot] = {"present": any(not r["inconclusive"] for r in recs.values()),
                     "source_checks": sorted(recs), "checks": recs,
                     "note": "OpenSSF Scorecard's automated results, relayed; scores are OpenSSF's, not the collector's"}
    meta = {"scorecard_version": (result.get("scorecard") or {}).get("version"),
            "repo": (result.get("repo") or {}).get("name"),
            "repo_commit": (result.get("repo") or {}).get("commit"), "date": result.get("date")}
    return obs, unmapped, meta


def collect(args):
    try:
        repo = normalize_repo(args.repo)
    except ValueError as e:
        sys.exit(str(e))
    if args.file:
        raw = open(args.file, "rb").read()
        access = "saved-api-response"
    else:
        try:
            raw = fetch(repo)
        except Exception as e:
            sys.exit("Scorecard API fetch failed for %s: %s (no package written; absence of a "
                     "result is not a result)" % (repo, e))
        access = "public-api:" + API.split("/")[2]
    result = json.loads(raw)
    obs, unmapped, meta = observe(result)
    now = bl.utcnow()
    os.makedirs(args.out_dir, exist_ok=True)
    raw_hash = ak.write_blob(args.out_dir, raw)
    source = {"tool": "openssf-scorecard", "kind": "third_party_automated", "repo": repo, **meta}
    prov = {"box": args.box or repo, "access": access}
    fresh = ak.freshness(now, meta["date"], "Scorecard's run date governs age, not the fetch time")
    items = []
    for slot in sorted(obs):
        items.append(ak.make_item(slot, "export", "third_party_attestation", False, source, prov,
                                  "attested", obs[slot], raw_hash, now, fresh,
                                  ak.mapped("scorecardmode.CHECK_SLOTS")))
    if unmapped:
        items.append(ak.make_item(
            ak.UNMAPPED, "export", "third_party_attestation", False, source, prov,
            "scorecard_unmapped_checks", {"present": True, "checks": unmapped}, raw_hash, now, fresh,
            ak.unmapped("Scorecard checks with no slot in the scorer evidence map",
                        sorted({UNMAPPED_CANDIDATES.get(n, "?") for n in unmapped}))))
    subject = {"name": args.subject or repo, "scope": "repo:" + repo, "collected_utc": now}
    collector = {"name": "beacon-scorecard-adapter", "version": "0.1.0", "platform": "any"}
    package, out_path = ak.seal_write(args, items, subject, collector)
    print("Scorecard %s for %s at %s (run %s), sha256 %s..." % (
        meta["scorecard_version"], repo, (meta["repo_commit"] or "?")[:12], meta["date"], raw_hash[:12]))
    ak.summarize(items, package, out_path)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--repo", required=True, help="github.com/OWNER/REPO (public)")
    c.add_argument("--file", help="saved Scorecard API JSON instead of a live fetch")
    ak.add_common(c, "out-scorecard")
    ak.add_verify(sub)
    a = ap.parse_args()
    (collect if a.cmd == "collect" else ak.cmd_verify)(a)
