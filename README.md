# Beacon Collector

An open-source, self-hosted tool an organization runs against **its own** systems to
**collect, collate, package, seal, and send** security-posture evidence. It **never scores**.
The output is a tamper-evident `vcri.beacon.evidence-package/v0` that the org owns: keep it
and self-score with the open scorer, or send it to VCRI escrow where Cairn Risk Co. produces
the verified rating.

The collector is VCRI's open adoption layer. The schema is VCRI's open standard (CC-BY).
Scoring is a separate layer (the open self-scorer, or CRC's verified rating). The collector
itself makes no judgment: it computes only freshness and completeness. See `SPEC.md` for the
eight locked invariants and the version roadmap.

## Install: as code or as a container

Both give you the same `beacon` command.

As code (Python 3.10 or later):

```bash
pip install git+https://github.com/value-chain-risk-institute/beacon-collector@v0.8.1   # or: pip install . from a checkout
beacon commands                         # every command, one line each
beacon sbom collect --sbom bom.json     # seal some evidence
beacon verify out-sbom/package.json     # check the seal
beacon results out-sbom/package.json    # one-page HTML results: score, evidence, gaps, fingerprint
```

As a container:

```bash
docker run --rm -v "$PWD:/work" -w /work ghcr.io/value-chain-risk-institute/beacon-collector:v0.8.1 results package.json
```

`docker run IMAGE <command> [args]` is `beacon <command> [args]`. With no command, the image
dogfoods the host as described below. The `scan` command needs Trivy on the PATH; the container
includes it, and pip users install it separately.

## Quick start (dogfood a box)

Requires Docker. On the box:

```bash
docker compose run --rm collector
```

That scans the box's own filesystem (mounted read-only at `/host`), maps the findings to
evidence slots, seals them, and verifies the seal on-box. The sealed package lands in `./out`.
**Nothing leaves the machine.**

Plain Docker, without compose:

```bash
docker run --rm --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v /:/host:ro -v "$PWD/out:/out" beacon-collector:dogfood
```

To sign the package with an enrolled identity key (anti-forge), enroll first (see `enroll.py`),
mount the key dir read-only, and set `BEACON_SIGN=1`.

## What the dogfood proves (and what it doesn't)

It **proves the pipeline**: real tools produce evidence, every item and the whole package is
content-hashed, and editing anything breaks `verify`. On a box you can touch, that is a stronger
demonstration than any slide.

It is **not** a vendor assessment. A single box has no vendors; "the box assessing itself" is a
mechanics demo. The value here is adoption (grab the repo, run it yourself) and validation (it
runs in the wild), not the telemetry from a conference box.

## Quick start for an organization (not the dogfood)

```bash
git clone https://github.com/value-chain-risk-institute/beacon-collector && cd beacon-collector
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
make test                                   # the tamper suites must pass on your box

python enroll.py                            # one-time identity key (anti-forge), kept by you
python collector.py collect --target / --subject "Acme" --box web-1 --sign --out-dir out/hosts
python exportmode.py collect --export okta-users.json --source idp --subject "Acme" --sign --out-dir out/idp
python docs.py collect --doc soc2-2026.txt --doc-type soc2 --subject "Acme" --sign --out-dir out/soc2
python merge.py --out-dir out/acme --sign out/hosts/package.json out/idp/package.json out/soc2/package.json

python anchor.py verify out/acme/package.json     # RFC 3161 token + OTS proof, offline
python score.py out/acme/package.json             # the free-tier score, work shown
```

Every `collect` seals and anchors at write time. Nothing is sent anywhere. To make it a
series, put the same three commands in `deploy/beacon-schedule.example.json` and install
one of the `deploy/` timers; `scheduled.py verify` then checks every seal, chain link and
anchor in the history. Sending to VCRI escrow (`send.py`) is the part not yet finished.

## Anchoring (what "sealed and anchored" means, as of 2026-09-12)

Every org mode (scanner, document, export, merge) anchors the package it just sealed
unless you pass `--no-anchor`. Anchoring is out of band: the seal is complete before
any anchor is attempted, an anchor service being down never stops a collection, and
the record says exactly what was and was not obtained. Beside `package.json` you get:

- `package.json.tsr`: an RFC 3161 timestamp token over the package bytes from an
  independent timestamp authority (freetsa.org). Verify with stock OpenSSL and the
  trust chain shipped in `anchor-trust/`:
  `openssl ts -verify -in package.json.tsr -data package.json -CAfile anchor-trust/freetsa-cacert.pem -untrusted anchor-trust/freetsa-tsa.crt`
- `package.json.ots`: an OpenTimestamps proof. It is `submitted` until a Bitcoin block
  includes it; run `anchor.py upgrade package.json` later (hours) to make the proof
  self-contained, then `ots verify package.json.ots`.
- `package.json.anchors.json`: the honest record. States are `pending`, `submitted`,
  `confirmed`, `failed`, never overstated. A token taken more than 60 s after sealing
  is marked `late_anchor` with the gap in seconds.

`anchor.py verify package.json` checks all of the above offline, the way a third party
would months later. Rekor (public transparency log) is gated off by default because a
Rekor entry is permanent and public; the record says so rather than pretending.

## Scheduled mode (posture as a series)

`scheduled.py run --config beacon-schedule.json` runs a configured list of collections
(scanner, document, export) and keeps every sealed package under an org-owned state
directory. Each package is chained to the previous one inside the sealed core
(`collector.chain.prev_package_hash`), anchored at write time, and pending
OpenTimestamps proofs are upgraded on later runs. `scheduled.py status` and
`scheduled.py verify` (every seal, every chain link, every anchor, offline). Deploy
templates for launchd, systemd and cron are in `deploy/`.

## The free reference scorer (the other side of the schema)

`score.py PACKAGE.json` verifies the package first (an invalid package is refused, not
scored), then applies the leveling rules in `scorer-evidence-map-v0.json` against the
mirrored VCRI rubrics in `rubrics/` and prints the free-tier score with its work shown.
The arithmetic is the questionnaire's. Two numbers are always printed together: the
comparable score (unscored subcriteria count as 0) and the covered score (over the
evidence present) with the coverage percentage. Evidence class is the ceiling: observed
evidence can reach level 4, an attestation is capped at 2, the subject's own claim at 1,
and level 5 is never awarded by the free scorer. Observed beats attested on the same
subcriterion and the disagreement is printed as a contradiction. Slots with no home in
the rubric are printed as gaps. The rules are VCRI's methodology, versioned and public;
the scorer only applies them.

## Security posture (why a public IP is fine)

**The collector is outbound-only. It opens no listening ports, except one loopback-only port (127.0.0.1) while the optional local UI (`ui.py`) is running.** `collect` shells out to Trivy
and writes local files; `send` (when used) is org-initiated and outbound. So the collector is
**not** the attack surface of a public-IP box.

What *is* the attack surface is the box itself: the OS, and whatever else runs on it (e.g.
Security Onion or Wazuh). Harden those independently. This image helps by refusing privilege it
does not need:

- runs as a non-root user (uid 10001)
- container filesystem read-only; only `/out` and `/tmp` are writable
- all Linux capabilities dropped; `no-new-privileges` set
- host filesystem mounted **read-only** (`/:/host:ro`): the collector can observe, never alter
- no published ports

## Files

`collector.py` scanner mode (Trivy) · `docs.py` document mode (SOC 2 / pen-test ingest) ·
`exportmode.py` export mode (IdP) · `enroll.py` Ed25519 identity + signing · `merge.py`
multi-box aggregation · `beaconlib.py` shared seal/sign/verify · `report.py` local report ·
`securityonion.py` Security Onion / Wazuh adapter (WIP) · `send.py` send layer (PQC channel WIP) · `anchors.py` + `anchor.py` timestamp/OTS/Rekor anchoring and offline verify · `scheduled.py` scheduled mode (series, chain, upgrade) · `score.py` free reference scorer (+ `scorer-evidence-map-v0.json`, `rubrics/`). Adapters (2026-09-30, `ADAPTER-ROADMAP.md`): `sbommode.py` SBOM · `scorecardmode.py` OpenSSF Scorecard · `outsidein.py` SPF/DMARC/TLS for your own domain · `exportcsv.py` Entra, Google Workspace, KnowBe4-style, AWS IAM CSV exports · `oscalmode.py` OSCAL JSON · `adapterkit.py` shared plumbing.

`SPEC.md` product spec + invariants · `EVIDENCE-SCHEMA-and-source-map-v0.1.md` data spec ·
`JAWNCON-MVP-PLAN.md` the deployment plan.

## License

Collector code: Apache License 2.0 (see `LICENSE`), self-hosted. Schema `vcri.beacon.evidence-package/v0`: CC-BY, VCRI.

## Overlays and coverage bundles (report.py)

`report.py PACKAGE.json --framework <name> [--md F] [--html F] [--json F] [--bundle DIR]`

Reads a sealed package (refuses a tampered one) and shows, per framework requirement, whether the package holds evidence that speaks to it and the class of that evidence: Observed (system of record or scanner), Attested (a third party's report, sealed), Stated (the subject's own claim, sealed, unverified). No score; never "compliant"; a map, not a blessing.

Standards are OVERLAYS: the same sealed evidence, with a standard's requirements laid over it. One collector, collect once; overlays live in `overlays/*.json`, versioned and public. (A crosswalk is the narrower thing: a map between two standards' requirement IDs, so one pointer satisfies several overlays.) Shipped: `cra-annex-i` (inline), `nist-sp800-171r2` (all 110 Rev. 2 requirements, from NIST's own list in `overlays/nist-sp800-171r2-security-reqs.source.csv`; 64 have a collector evidence slot today, 46 need Recorded or Stated evidence attached). `--bundle` writes a directory a third party can open: the package (and blobs), the coverage in md/json/html, and a README with the verify command.

Sample: `python3 samples/make_sample_171.py && python3 report.py samples/sample-171-package.json --framework nist-sp800-171r2 --bundle samples/bundle-171-sample` (synthetic supplier, every item labelled synthetic).

### Span pointers (point.py)

"I think these lines answer this requirement." `point.py` seals exactly that sentence: a pointer from a named person to a line range and quoted span in a hashed document, keyed to a framework requirement (`nist-sp800-171r2:3.2.1`). It is Stated class: a claim, not an evaluation, and the natural precursor to a paid examination that confirms or refuses it. A model may suggest a pointer (`--model`); it is shown as suggested and never counted until a person re-points it (`--by`). Merge pointer packages into the main package with `merge.py`; the coverage report then shows `pointed` rows with the lines and the quote. Editing a quote after sealing fails verification.

`point.py --doc policy.pdf --framework nist-sp800-171r2 --subject-json subject.json --by "Name, role" --claim "3.2.1|14-17|quoted span" --out-dir pointers`

## Local UI (ui.py)

`~/.beacon/venv/bin/python ui.py serve [--state ~/.beacon/agent] [--port 0] [--idle-minutes 30]`

A loopback-only admin console over the evidence already sealed: Status (chain head, sequence, last seal, heartbeat due, signing, anchor counts, the max-gap blind window), Sources (every element of the newest package, absent ones shown, never hidden), Timeline (the `beacondiff` change ribbon for the last N packages), Packages (items with evidence class, completeness and freshness, plus Verify, which reports exactly one of verified, tampered or unproven), and Export (a `report.py` bundle written to a new directory under `~/.beacon/exports/`). It adds no measurement of its own and has no route that edits or deletes evidence. Standard library only.

While it runs, the collector has one listening port, bound to 127.0.0.1. A non-loopback bind is refused unless `--allow-remote` is given; remote viewing is an SSH or Tailscale tunnel. The printed launch URL carries a per-launch token that is exchanged for an HttpOnly, SameSite=Strict cookie; requests with any other Host header are refused; export is POST only with a CSRF token and an Origin check; no CORS headers; CSP allows no script. Signing is reported without reading the keychain, so it can say unknown. The process exits after 30 idle minutes. Tests: `~/.beacon/venv/bin/python test_ui.py`.

## Agent actions (v0.3, branch v0.3-actions)

Agent mode now seals what the agent did, not only how it was configured. Five new items:

- H18 agent-action-ledger: prompts, model turns, tool calls and results from two claim sources, the Claude Code hook (`hooks/beacon_action_hook.py`, hash-chained daily spool) and the Claude Code transcripts (`sources/claude_transcripts.py`, sealed prefixes so a rewritten transcript is a located finding). Graded as the agent's own account. Transcript capture is off unless the operator names a root with `BEACON_TRANSCRIPT_ROOT`; on a box where agents are persons, not tools, it stays off, and H18 records that as a boundary.
- H19 vendor record, H20 OS-observed effects, H21 cloud credential activity: recorded as absent until a source is configured.
- H22 action-pairing delta: derived set arithmetic over H18 (which calls each source saw, and whether their committed inputs agree).

A2 now has a real source: the served model per turn from the API response field, next to the requested model.

Content is never stored. Each prompt, tool input and tool output becomes `c1:sha256(nonce || bytes)`, with a per-item nonce derived from a per-deployment key in `<state>/actions/commit.key`. The org can open one item for an examiner (`reconstruct.py open`) without revealing the key or any other item; the examiner checks it with no key (`reconstruct.py timeline --openings`).

Installing the hook changes the live harness, so it is an operator decision. To try it without touching user settings, pass a settings file to one session:

    claude --settings hook-settings.json ...

where hook-settings.json registers, for SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, PostToolUseFailure and Stop, the command
`BEACON_STATE=~/.beacon/agent ~/.beacon/venv/bin/python <repo>/hooks/beacon_action_hook.py`. The hook never blocks, never prints, and always exits 0.

Tests: `~/.beacon/venv/bin/python test_agentmode.py` (includes the canonicalization stability gate over every sealed package on the machine: zero mismatches required).
