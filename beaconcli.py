#!/usr/bin/env python3
"""
beaconcli.py, Beacon Collector: the single `beacon` command.

Same commands whether you installed with pip or run the container:

  beacon <command> [args...]       run one tool (each tool keeps its own --help)
  beacon verify PACKAGE.json       verify a sealed package's hashes, Merkle root, signature
  beacon commands                  list every command
  beacon version

Each command is an existing module run exactly as if you had typed
`python3 <module>.py args...`, so behavior is identical to the scripts.
"""
import os
import runpy
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)  # the modules import each other by bare name

VERSION = "0.8.0"
CREDIT = "Beacon Collector by The Value Chain Risk Institute. Inside data, not guesses. https://valuechainrisk.org"

# command -> (module, one-line description). Grouped by what a beta user does first.
COMMANDS = [
    ("scan", "collector", "Scan a target with Trivy and seal the findings"),
    ("sbom", "sbommode", "Seal an SBOM (CycloneDX or SPDX JSON)"),
    ("csv", "exportcsv", "Seal identity, MFA, training, or IAM CSV exports"),
    ("export", "exportmode", "Seal a system-of-record export (IdP, MDM)"),
    ("oscal", "oscalmode", "Seal an OSCAL SSP, assessment results, or POA&M"),
    ("scorecard", "scorecardmode", "Seal OpenSSF Scorecard results for a repo"),
    ("outside-in", "outsidein", "Seal SPF, DMARC, and TLS for a domain you own"),
    ("documents", "docs", "Seal a SOC 2 or pen-test report as an attestation"),
    ("point", "point", "Seal span pointers from a document to a framework requirement"),
    ("ai-usage", "aiusage", "Seal AI service use observed in network logs"),
    ("security-onion", "securityonion", "Seal evidence from a Security Onion export"),
    ("agent", "agentmode", "Continuous collection for an agentic AI deployment"),
    ("reconstruct", "reconstruct", "Turn sealed agent-action packages into a timeline"),
    ("merge", "merge", "Merge packages from several machines into one"),
    ("scheduled", "scheduled", "Collect on a schedule with a hash-chained series"),
    ("diff", "beacondiff", "Compare two packages, or show a package timeline"),
    ("score", "score", "Score a sealed package (open reference scorer, text)"),
    ("results", "results", "Write the one-page HTML results for a sealed package"),
    ("report", "report", "Framework coverage report for a sealed package"),
    ("anchor", "anchor", "Timestamp, upgrade, or verify a package's public anchors"),
    ("enroll", "enroll", "Create or show this collector's identity"),
    ("send", "send", "Send a package with hybrid post-quantum encryption"),
    ("ui", "ui", "Local admin console"),
]
# Added only if present in this build (the document ingester ships on its own branch).
OPTIONAL = [("ingest", "ingestmode", "Map policy documents to framework clauses (human confirms)")]


def available():
    out = list(COMMANDS)
    for c in OPTIONAL:
        if os.path.isfile(os.path.join(HERE, c[1] + ".py")):
            out.append(c)
    return out


def usage(stream=sys.stdout):
    print("usage: beacon <command> [args...]   (beacon <command> --help for details)\n", file=stream)
    for name, _, desc in available():
        print("  %-15s %s" % (name, desc), file=stream)
    print("  %-15s %s" % ("verify", "Verify a sealed package (hashes, Merkle root, signature)"), file=stream)
    print("  %-15s %s" % ("version", "Print the version"), file=stream)
    print("\n" + CREDIT, file=stream)


def verify(args):
    import argparse
    import json
    import beaconlib as bl
    ap = argparse.ArgumentParser(prog="beacon verify", description="Verify a sealed Beacon package.")
    ap.add_argument("package")
    ap.add_argument("--registry", help="enrollment registry directory, to check the signer")
    ap.add_argument("--blobs", help="raw blob directory (default: blobs/ beside the package)")
    a = ap.parse_args(args)
    with open(a.package) as f:
        pkg = json.load(f)
    blob_dir = a.blobs or os.path.join(os.path.dirname(os.path.abspath(a.package)), "blobs")
    ok = bl.verify_package(pkg, blob_dir=blob_dir, registry=a.registry)
    print("VERIFIED" if ok else "REFUSED: package does not verify")
    print("package fingerprint: %s" % (pkg.get("seal", {}) or {}).get("package_hash"))
    return 0 if ok else 2


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help", "commands"):
        usage()
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd in ("version", "--version"):
        print("beacon-collector %s" % VERSION)
        return 0
    if cmd == "verify":
        return verify(rest)
    if cmd == "dogfood":  # the container's original default: scan the host it runs on
        script = os.path.join(HERE, "dogfood.sh")
        os.execv("/bin/sh", ["/bin/sh", script] + rest)
    table = {name: mod for name, mod, _ in available()}
    if cmd not in table:
        print("beacon: unknown command %r\n" % cmd, file=sys.stderr)
        usage(sys.stderr)
        return 2
    mod = table[cmd]
    sys.argv = ["beacon " + cmd] + rest
    try:
        runpy.run_path(os.path.join(HERE, mod + ".py"), run_name="__main__")
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
