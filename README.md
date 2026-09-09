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
`securityonion.py` Security Onion / Wazuh adapter (WIP) · `send.py` send layer (PQC channel WIP).

`SPEC.md` product spec + invariants · `EVIDENCE-SCHEMA-and-source-map-v0.1.md` data spec ·
`JAWNCON-MVP-PLAN.md` the deployment plan.

## License

Collector: open source (self-hosted). Schema `vcri.beacon.evidence-package/v0`: CC-BY, VCRI.
