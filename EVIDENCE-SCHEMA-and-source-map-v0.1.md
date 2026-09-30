# BeaconScore Evidence Schema + Source Map v0.1

*2026-07-28. The open schema an evidence collector emits (and CRC / the open scorer consume). Doug-ready: this is what a Security Onion "posture export" would produce. Collector does collect→package→seal→send, NEVER rate. Scoring + Greeks = CRC. Schema = VCRI, open (CC-BY).*

## Design invariants
- **Collector never scores.** It captures evidence, maps it to a subcriterion *slot*, seals it, sends it. The 0-5 leveling is done downstream (open scorer or CRC), from the sealed evidence.
- **Seal = the trust anchor.** Each evidence item and the whole package is content-hashed (SHA-256), signed, and (at grading) Merkle-anchored. The subject cannot alter evidence after collection.
- **Three collection modes**, and the schema is mode-agnostic:
  - `scanner` — a tool run produces machine output (Trivy, Wazuh SCA, osquery, OpenSCAP, sslyze, Prowler, Garak)
  - `export` — a pull from a system of record (IdP, IGA, PAM, ITSM, LMS, backup, badge system)
  - `document` — an artifact ingested + parsed (SOC 2, pen test, policy, IR plan, model card)
- **Highest-leverage source: audit artifacts.** One SOC 2 Type II / pen-test report spans dozens of subcriteria across rubrics. Document mode is prioritized for *breadth*; scanner mode for *live, verifiable depth* (VCRI's differentiator over a static SOC 2).

## The emittable evidence bundle (schema)
```json
{
  "schema": "vcri.beacon.evidence-package/v0",
  "subject": {"name": "...", "scope": "...", "collected_utc": "..."},
  "collector": {"name": "...", "version": "...", "platform": "linux|windows|macos|cloud"},
  "items": [
    {
      "subcriterion": "technology-v1:1.1a",        // slot it maps to; NOT a score
      "mode": "scanner|export|document",
      "source": {"tool": "trivy", "kind": "sbom", "raw_sha256": "..."},
      "observation": { /* normalized facts: e.g. packages_enumerated, sbom_present, signed */ },
      "context": [                                  // OPTIONAL subject assertions — NOT verified evidence
        {
          "type": "note | risk_acceptance | compensating_control",
          "text": "IAM is minimal by design — 2-person org; least-privilege overhead exceeds benefit at this scale.",
          "rationale": "...", "compensating_control": "...",
          "asserted_by": "name/role", "asserted_utc": "...",
          "verified": false, "epistemic": "subject_claim"   // captured & sealed, but a CLAIM, not a capture
        }
      ],
      "artifact_ref": "blob/sha256-...",            // the raw output/doc, hashed
      "collected_utc": "..."
    }
  ],
  // RULE: `context` is sealed with the package (tamper-evident) but is a subject CLAIM.
  // The open self-scorer IGNORES it. A CRC assessor (human) MAY weigh it. Notes never
  // auto-adjust a level — else they become a fake-your-grade vector.
  "seal": {"alg":"sha256","package_hash":"...","signature":"...","anchor":"opentimestamps:..."}
}
```
Downstream (open scorer or CRC) reads `observation` per subcriterion, applies the published rubric anchors, and produces the 0-5 level + grade. The collector supplies facts; the scorer supplies judgment.

## Source map — evidence → mode → open-source tool, per rubric

### Technology (mostly `scanner`)
| subcriterion | evidence | mode | tool |
|---|---|---|---|
| 1.1a inventory/SBOM/provenance | package inventory, SBOM, signing attestation | scanner | Trivy/Syft, osquery |
| 1.1b config baseline & integrity | CIS/STIG config checks, drift | scanner | Wazuh SCA, OpenSCAP, CIS-CAT |
| 1.1c third-party/supply-chain trust | dependency provenance, vendor components | scanner+document | Trivy, deps.dev, SOC 2 |
| 2.2a/b system auth & PAM | auth config, privileged accounts | export | IdP export, PAM export, osquery |
| 3.3a data-in-transit/at-rest | TLS posture, disk-encryption state | scanner | sslyze/testssl.sh, osquery |
| 4.4a vuln/patch mgmt | vuln findings, patch age | scanner | Trivy/Grype, OpenVAS, patch-mgmt export |
| 4.4b endpoint/EDR | EDR presence/coverage | scanner+export | osquery, EDR console export |
| 4.4c network controls | firewall/IPS/egress config | export+document | config export, network diagram |
| 6.6a/b SIEM & IR | log coverage, detections | export | SIEM coverage report |
| 6.6c secure SDLC | pipeline security, hardening | scanner+document | Trivy IaC, SDLC policy |

### Data (`scanner` + `export` + `document`)
- classification & labeling (document: classification standard; export: DLP labels)
- encryption at rest/in transit + key mgmt (scanner: TLS/disk; export: KMS/HSM config)
- PII/PHI discovery & inventory (scanner: data-discovery tools)
- DLP & egress (export: DLP config)
- backup/recovery RPO/RTO (export: backup-software reports)
- retention & defensible deletion (document: retention schedule)
- crypto-agility/PQC readiness (document: crypto inventory) — no clean scanner yet

### People (mostly `export` + `document`)
- MFA coverage & auth strength (export: IdP — Okta/Entra/Duo)
- joiner-mover-leaver / access reviews (export: IGA)
- privileged access & least privilege (export: PAM)
- security-awareness training + phishing results (export: LMS — KnowBe4 etc.)
- background screening (document: policy + attestation)
- SoD / role clarity (document: RACI, org chart)
- offboarding integrity (export: IGA/IdP deprovision logs)

### Processes (mostly `document` + `export`)
- policies / procedures / standardization (document: the policy set)
- change mgmt & provenance (export: ITSM change tickets — Jira/ServiceNow)
- SoD & approval gates (export: workflow/approvals)
- incident response plan + post-mortems (document + export: IR tickets)
- BC/DR plan + test reports (document)
- control-effectiveness measurement / audit (document: SOC 2, internal audit, pen test)
- risk register (document/export: GRC — eramba)

### Facilities (mostly `document` + physical `export`)
- facility/OT inventory (export: asset system; document: inventory)
- physical access control + logs (export: badge system)
- OT/building-system segmentation (scanner: passive OT scan; document: network arch)
- environmental (power/HVAC/fire) (document: monitoring reports)
- data-center/colo certifications (document: colo SOC 2 / attestation)
- OT patch & failsafe (document + export)

### AI / Cognitive security (emerging: `scanner` + `document`)
- model inventory / AI-BOM (scanner: CycloneDX ML-BOM; document: model cards)
- model artifact integrity (scanner: signing/attestation — cosign/in-toto)
- training-data provenance (document: data lineage)
- prompt-injection / red-team results (scanner: Garak, PyRIT)
- tool allow-listing + agent identity/authz (export: agent config)
- memory-write provenance (export: system logs/config)
- AI governance program (document: NIST AI RMF / ISO 42001 policy)

## Assembly recommendation (from the survey)
- **Spine: Wazuh** (Security Onion's own engine) — cross-platform agents, SCA/CIS, FIM. Use directly, standalone, not the whole Security Onion distro.
- **Supply chain: Trivy/Syft/Grype.** **Inventory: osquery** (+ Fleet as an aggregation UI candidate). **Config: OpenSCAP/CIS-CAT.** **Cloud: Prowler/ScoutSuite/Steampipe.** **AI: Garak.** **GRC/risk: eramba.**
- **Document collector: build (small) or find** — ingests SOC 2 / pen test / policies / IR plans, parses + maps to slots (LLM-assisted), hashes each artifact. Highest breadth per unit effort. This is the "policy ingester."
- **UI: aggregate → review → package → send.** Fleet is a candidate base for the endpoint side; the document + packaging layer is ours.
- **Security Onion channel:** get Doug to add a "posture export" emitting THIS schema → every Security Onion install becomes a feeder. Bounded ask (emit the schema), not a dependency.

## Enrollment + trust + send layer (design; build after Trivy adapter)

**Threat Joshua named:** if the enrollment seed is exchanged over non-PQC, harvest-now-decrypt-later exposes it. **Resolution: out-of-band seed.** The seed never traverses a harvestable channel.

**Lifecycle:** download collector → **enroll** (paste one-time token from VCRI portal, shown in the authenticated web UI — eyeball-to-keyboard, like a Tailscale/Wazuh/GitHub-runner key) → collector opens a hybrid-PQC channel (X25519 + ML-KEM/Kyber, FIPS 203) and receives a long-term collector identity key → **collect** (scanner/export/document, one or many boxes) → **seal** (SHA-256 + sign) → **PQC-encrypt** (hybrid; AES-256-GCM payload) → **send** (VCRI escrow, or org keeps + self-scores; org-controlled, never forced phone-home).

**Trust math (complete):**
- hash seal = anti-EDIT (proven in spike 0)
- enrollment identity = anti-FORGE / anti-SUBSTITUTE (only an enrolled collector's key yields a valid package)
- hybrid PQC = confidentiality in transit + harvest-now-decrypt-later hedge
- out-of-band seed = safe bootstrap (no harvestable exchange)

**Two DISTINCT trust relationships (do not conflate):**
1. Collector ↔ VCRI — the enrollment seed, one per collector instance.
2. Collector ↔ each target box — separate per-target access (SSH/API creds, or a Wazuh-style sub-agent enrolled to the collector). Multi-box: record which box each evidence item came from (provenance per item).

**Build rules:** never roll our own crypto — use vetted liboqs (hybrid). PQC is a hardening block AFTER the Trivy adapter, not spike 0. Enrollment server is a small VCRI-side service (token issue + collector registry). Collector stays open-source; the enrollment/registry + scoring/Greeks are the VCRI/CRC side.

## Next
1. Nail the `evidence-package/v0` schema (this doc's JSON) as the CC-BY spec — it's what Doug builds against and what the scorer/CRC consume.
2. Fix spike 0: remove the scoring; collector emits the sealed evidence package, no level.
3. One tool at a time: Trivy adapter → Wazuh adapter → document collector.

## Addendum 2026-09-30: the "recorded" evidence class (Joshua's decision)

New item-level epistemic label `recorded_export`, scored as class `recorded`, cap 3 (observed 4 > recorded 3 > attested 2 > stated 1). Recorded means system-generated records of past activity that the org exports (training completions, phishing-simulation results, restore-job history, change tickets): stronger than a claim because a system wrote it at the time, weaker than observed because the org chooses the export and it describes the past, not current state. First users: exportcsv `training` and `phishing` sources.
