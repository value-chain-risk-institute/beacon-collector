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
git clone https://github.com/Cairn-works/beacon-collector && cd beacon-collector
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

**The collector is outbound-only. It opens no listening ports.** `collect` shells out to Trivy
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
`securityonion.py` Security Onion / Wazuh adapter (WIP) · `send.py` send layer (PQC channel WIP) · `anchors.py` + `anchor.py` timestamp/OTS/Rekor anchoring and offline verify · `scheduled.py` scheduled mode (series, chain, upgrade) · `score.py` free reference scorer (+ `scorer-evidence-map-v0.json`, `rubrics/`).

`SPEC.md` product spec + invariants · `EVIDENCE-SCHEMA-and-source-map-v0.1.md` data spec ·
`JAWNCON-MVP-PLAN.md` the deployment plan.

## License

Collector: open source (self-hosted). Schema `vcri.beacon.evidence-package/v0`: CC-BY, VCRI.

## Framework coverage bundles (report.py)

`report.py PACKAGE.json --framework <name> [--md F] [--html F] [--json F] [--bundle DIR]`

Reads a sealed package (refuses a tampered one) and shows, per framework requirement, whether the package holds evidence that speaks to it and the class of that evidence: Observed (system of record or scanner), Attested (a third party's report, sealed), Stated (the subject's own claim, sealed, unverified). No score; never "compliant"; a map, not a blessing.

Crosswalks live in `crosswalks/*.json`, versioned and public. Shipped: `cra-annex-i` (inline), `nist-sp800-171r2` (all 110 Rev. 2 requirements, from NIST's own list in `crosswalks/nist-sp800-171r2-security-reqs.source.csv`; 64 have a collector evidence slot today, 46 need Recorded or Stated evidence attached). `--bundle` writes a directory a third party can open: the package (and blobs), the coverage in md/json/html, and a README with the verify command.

Sample: `python3 samples/make_sample_171.py && python3 report.py samples/sample-171-package.json --framework nist-sp800-171r2 --bundle samples/bundle-171-sample` (synthetic supplier, every item labelled synthetic).

### Span pointers (point.py)

"I think these lines answer this requirement." `point.py` seals exactly that sentence: a pointer from a named person to a line range and quoted span in a hashed document, keyed to a framework requirement (`nist-sp800-171r2:3.2.1`). It is Stated class: a claim, not an evaluation, and the natural precursor to a paid examination that confirms or refuses it. A model may suggest a pointer (`--model`); it is shown as suggested and never counted until a person re-points it (`--by`). Merge pointer packages into the main package with `merge.py`; the coverage report then shows `pointed` rows with the lines and the quote. Editing a quote after sealing fails verification.

`point.py --doc policy.pdf --framework nist-sp800-171r2 --subject-json subject.json --by "Name, role" --claim "3.2.1|14-17|quoted span" --out-dir pointers`
