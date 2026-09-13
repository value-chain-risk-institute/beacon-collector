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
