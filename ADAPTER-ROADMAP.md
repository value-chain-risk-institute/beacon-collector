# Beacon Collector adapter roadmap

Joshua Marpet and Cairn Viktor, 2026-09-30. Companion to `SPEC.md` (product), `EVIDENCE-SCHEMA-and-source-map-v0.1.md` (data) and `scorer-evidence-map-v0.json` (the slots the open scorer reads). Status is as of branch `adapters-easy-2026-09-30` (local, not pushed); verify on disk before quoting it.

## How to read this

Slot ids are the ones the scorer evidence map already knows (`technology-v1:1.1a`, `people-v1:mfa`, and so on). Where a source's evidence has no slot, the table says `unmapped` and names the rubric key a methodology decision could give it (for example `people-v1/4b`); adapters emit such evidence with `subcriterion: "unmapped"` and a `mapping.reason`, and `score.py` prints it as a gap. No adapter invents a slot id.

Evidence class uses the house labels: `observed_scan` and `observed_export` (Observed), `third_party_attestation` (Attested), `subject_claim` (Stated). Observed is what the collector itself saw or pulled from a system of record; Attested is someone else's report relayed and sealed; Stated is the organization's own claim.

Ranking weighs three things, in this order: the value of the Observed evidence the source produces (does it move a slot from Stated or Attested to Observed), how common the source is among small and mid-sized vendors, and how cheap it is to build and test honestly.

Effort: S is under about 200 lines plus tests and testable without anyone's credentials; M needs an API client, pagination, and a sandbox tenant or recorded fixtures; L needs a new collection technique or multi-OS work.

## Design rules (every adapter)

1. Read-only, least privilege. Ask for the narrowest read scope the vendor offers; name it in the adapter's docstring and in this file. If a vendor has no read-only scope, prefer the export file the admin downloads over an API token.
2. Credentials never leave the organization's machine. The collector runs on the org's hardware; tokens are read from the environment or a local file, never written into a package, a blob, a log, or a sent payload. File-export adapters hold no credentials at all.
3. Every item is labeled with its evidence class (`epistemic`), and `verified_by_collector` says whether the collector observed the fact or only verified the integrity of someone else's statement.
4. Adapters read and never write. No remediation, no configuration change, no ticket creation, no "fix it" button. An adapter that needs write scope to read is redesigned or dropped.
5. Build to the pilot's stack. Order below is a default; the first pilot's actual IdP, cloud, EDR and ticketing systems jump the queue.
6. Same trust path as every mode: raw output stored as a sha256-named blob, items sealed by `beaconlib.build_package` and `seal_and_sign`, anchored by `beaconlib.anchor_after_write`, verified by `beaconlib.verify_package`. Every adapter ships with a tamper test that must fail.
7. Never rate (Invariant 1). A source's own roll-up score (Scorecard's aggregate, Secure Score's percentage, a GRC tool's "readiness") stays in the sealed raw blob; observations carry per-check facts labeled as the source's.
8. Absence is a fact (Invariant 5). A source that returns nothing is recorded as returning nothing; a fetch that fails writes no package rather than an empty one that could be read as "clean".

## Built

| Source | File | Evidence (slots) | Class | Access | Least-privilege permission | Prevalence (SMB/mid) | Effort | Status |
|---|---|---|---|---|---|---|---|---|
| Trivy (inventory, vulns, misconfig) | `collector.py` | technology-v1:1.1a, 4.4a, 1.1b | observed_scan | CLI | read access to the scanned filesystem | High (free) | S | built 07-29 |
| IdP user export (Okta/Entra/Duo JSON shape) | `exportmode.py` | people-v1:mfa, least-privilege, jml | observed_export | export file | admin downloads the file; collector holds nothing | High | S | built 07-29 |
| SOC 2 / pen-test report | `docs.py` | 10+ slots via SOC 2 crosswalk | third_party_attestation | document | none | High | S | built 07-29 |
| Security Onion / Wazuh posture | `securityonion.py` | 3 slots | observed_export | API | read-only analyst | Low to mid | M | WIP spike |
| SBOM, CycloneDX JSON and SPDX JSON | `sbommode.py` | technology-v1:1.1a | subject_claim | file from the vendor | none | Mid, rising (CRA, EO 14028 buyers) | S | built 09-30 |
| OpenSSF Scorecard | `scorecardmode.py` | technology-v1:6.6c, process-v1:change-management, technology-v1:4.4a, technology-v1:1.1a; other checks unmapped (technology-v1/1x, 1c, processes-v1/1a) | third_party_attestation (source.kind `third_party_automated`) | public API, or saved response | none (public, no auth) | Any vendor with public repos | S | built 09-30 |
| Outside-in: SPF, DMARC, TLS on one named domain | `outsidein.py` | data-v1:in-transit (TLS); SPF and DMARC unmapped | observed_scan, `provenance.access: external-vantage` | DNS + one TLS handshake | none; the operator names only a domain it owns | Universal | S | built 09-30 |
| Microsoft Entra MFA registration report (CSV) | `exportcsv.py --source entra-mfa` | people-v1:mfa (registration basis), people-v1:least-privilege (admin flag) | observed_export | CSV the admin downloads | Reports Reader role in the portal; collector holds nothing | Very high | S | built 09-30 |
| Google Workspace user list (CSV) | `exportcsv.py --source gworkspace-users` | people-v1:mfa (2SV enrolled, enforced kept beside), people-v1:jml (suspended still present) | observed_export | CSV the admin downloads | admin with Users read privilege; collector holds nothing | High | S | built 09-30 |
| KnowBe4-style training and phishing results (CSV) | `exportcsv.py --source training / phishing` | unmapped (people-v1/4b, 5b, 4c) | observed_export | CSV the admin downloads | console reporting access | High | S | built 09-30 |
| AWS IAM credential report (CSV) | `exportcsv.py --source aws-iam-credential-report` | people-v1:mfa (console users, root MFA), technology-v1:2.2a (access key age and use) | observed_export | CSV the admin generates | `iam:GenerateCredentialReport`, `iam:GetCredentialReport` | High among cloud vendors | S | built 09-30 |
| OSCAL JSON: SSP, Assessment Results, POA&M | `oscalmode.py` | via indicative 800-53 crosswalk: people-v1:mfa, jml, least-privilege, technology-v1:2.2a, 1.1a, 1.1b, 4.4a, 4.4b, 4.4c, 6.6a, 6.6c, process-v1:change-management, control-effectiveness, incident-response (gap), data-v1:in-transit, backup-recovery, retention; others unmapped | SSP and POA&M subject_claim; AR third_party_attestation (subject_claim with `--self-assessed`) | file | none | Low among SMB, high among federal suppliers (FedRAMP) | S | built 09-30 |

Notes on the built set:

- Entra, Google, KnowBe4 and AWS CSV header aliases come from vendor documentation (AWS's credential report columns are documented exactly; the others are best effort) and have not been checked against a real tenant's download. An unrecognized header fails loudly. First pilot download fixes them.
- Entra's registration report says a user has registered MFA, not that sign-in requires it. Enforcement is Conditional Access, which is the Graph adapter below. The item says `basis: registration`.
- OSCAL XML and YAML are out of scope; convert with NIST's `oscal-cli` first. OSCAL component definitions and assessment plans are not read yet. The 800-53 crosswalk in `oscalmode.py` is indicative v0.1 and covers 22 control ids; everything else lands in the unmapped item with its control ids listed.
- The outside-in adapter does three lookups and one handshake against a domain the operator names. It does no port scan, crawl, or discovery. SPEC lists "BitSight-style outside-in scanning" as a non-goal; this is the organization checking its own front door, and exposed-port scanning stays out for that reason (see Skipped).

## Planned, ranked

| Rank | Source | Evidence (slots) | Class | Access | Least-privilege read permission | Prevalence (SMB/mid) | Effort | Priority |
|---|---|---|---|---|---|---|---|---|
| 1 | Microsoft 365 / Entra via Microsoft Graph: Conditional Access (MFA enforcement), directory roles, user lifecycle, Secure Score controls | people-v1:mfa (enforcement basis), least-privilege, jml; technology-v1:2.2a; Secure Score per-control facts unmapped until mapped | observed_export | API (app registration, certificate credential) | `Policy.Read.All`, `RoleManagement.Read.Directory`, `User.Read.All`, `AuditLog.Read.All`, `SecurityEvents.Read.All`; application permissions, read only | Very high | M | P1 |
| 2 | HR system JML cross-check (BambooHR, Rippling, Gusto export) joined to an IdP export | people-v1:jml (leavers with active accounts, days from termination to disable); unmapped people-v1/6c | observed_export | two export files, or HR API | HR: read-only report or API key limited to directory and termination date; IdP: as above | High | S | P1 (needs one pilot's HR export to fix the join key: work email vs employee id) |
| 3 | GitHub / GitLab org settings | process-v1:change-management (branch protection, required reviews), technology-v1:6.6c, technology-v1:4.4a (Dependabot and secret-scanning alert age), people-v1:mfa (org 2FA requirement) | observed_export | API | GitHub App or fine-grained token, read only: Administration, Organization administration, Dependabot alerts, Secret scanning alerts, Code scanning alerts. GitLab: `read_api`, role with security dashboard access | High among software vendors | M | P1 |
| 4 | Wazuh (SCA, vulnerability, FIM) | technology-v1:1.1b (the real config baseline source SPEC 0.5 names), 4.4a, 1.1a; FIM unmapped (technology-v1/5a) | observed_scan | Wazuh API and indexer | built-in `readonly` API role; read-only indexer user | Mid (free, Invariant 6 spine) | M | P1 |
| 5 | EDR coverage (Defender for Endpoint, CrowdStrike, SentinelOne) joined to MDM inventory (Intune, Jamf, Kandji) | technology-v1:4.4b (agent present, healthy, last seen, per managed device); technology-v1:1.1a device inventory | observed_export | API or console export | Defender: `Machine.Read.All`; CrowdStrike: Hosts read; SentinelOne: Viewer; Intune: `DeviceManagementManagedDevices.Read.All`; Jamf: API role with Read Computers; Kandji: device list read token | High | M | P2 |
| 6 | Google Workspace Admin SDK (API form of the built CSV) | people-v1:mfa (enrolled and enforced), least-privilege (isAdmin), jml | observed_export | API | `admin.directory.user.readonly` via a service account with domain-wide delegation limited to that scope | High | S to M | P2 (the CSV covers it until a pilot wants scheduled pulls) |
| 7 | Cloud posture: Prowler (AWS, Azure, GCP), AWS Security Hub, Microsoft Defender for Cloud, GCP Security Command Center | technology-v1:1.1b, 4.4c, 4.4a; data-v1:in-transit; people-v1:least-privilege | observed_scan (Prowler run by the collector) or third_party_attestation (a cloud provider's findings relayed) | CLI or API | AWS `SecurityAudit` + `ViewOnlyAccess`; Security Hub `AWSSecurityHubReadOnlyAccess`; Azure Security Reader; GCP `roles/securitycenter.findingsViewer` | High among SaaS vendors | M | P2 (SPEC 0.8) |
| 8 | Vulnerability scanners: Tenable, Qualys, Greenbone/OpenVAS | technology-v1:4.4a (scan recency, critical-finding age, assets scanned vs inventory) | observed_scan | API or report export | Tenable basic (read) user; Qualys reader; Greenbone Observer role | Mid | M | P2 |
| 9 | Logging coverage and retention (Splunk, Elastic, Microsoft Sentinel); never raw logs | technology-v1:6.6a (sources reporting, last event per source, retention days) | observed_export | API | Splunk role with `indexes_list_all` and metadata search only; Elastic `monitor` + `view_index_metadata`; Sentinel Log Analytics Reader | Mid | M | P2 |
| 10 | Backup tools (Veeam, AWS Backup, M365 backup vendors) | data-v1:backup-recovery (last success per protected set, last restore test) | observed_export | API or job report export | Veeam Backup Viewer; AWS `AWSBackupAuditAccess`-style read; vendor viewer role | High | M | P2 |
| 11 | osquery | technology-v1:1.1a (fleet inventory), technology-v1:4.4b (agent presence); disk encryption unmapped (technology-v1/3a) | observed_scan | local CLI or Fleet API | root on the host to see everything (coverage gap recorded when not root); Fleet observer role | Low to mid | M | P3 (SPEC 0.8) |
| 12 | Runtime observation module | technology-v1:1.1a Observed, compared against the SBOM (Stated) from `sbommode.py` | observed_scan | local snapshot per OS | root/admin; gap recorded without it | n/a (our module) | L | PARKED until the first pilot with Linux servers (`SPEC-runtime-observation-module-v0.1.md`) |
| 13 | Microsoft Intune / Jamf / Kandji as standalone MDM (compliance, encryption, OS currency) | technology-v1:1.1b (device compliance), 4.4a (OS patch level); encryption unmapped (technology-v1/3a) | observed_export | API | as in rank 5 | High | M | P3 (after EDR join) |
| 14 | Jira / ServiceNow change tickets | process-v1:change-management (changes with approval, approver not author) | observed_export | API | Jira: Browse Projects on the change project; ServiceNow: `snc_read_only` plus read ACL on `change_request` | Mid | M | P3 |
| 15 | PagerDuty / Opsgenie incident records | process-v1:incident-response (GAP: no rubric home; see Gaps) | observed_export | API | PagerDuty read-only API key; Opsgenie key with Read only | Mid | S to M | P3, blocked on the rubric decision |
| 16 | Sigstore / SLSA provenance | technology-v1:1.1a `signed_attestation` (the only Observed path to that step) | observed_scan (the collector verifies the signature itself) | CLI (`cosign verify`, `slsa-verifier`) or library | none for public artifacts | Low, rising | M (needs a vetted verifier; Invariant 7 forbids our own crypto) | P3 |
| 17 | AI red team: Garak, PyRIT, promptfoo | unmapped (ai-cogsec-v1/3a, 2b, 4b, 1e): no ai-cogsec slot in the evidence map yet | observed_scan when the org runs the tool on its own model; third_party_attestation when relayed | report files (Garak JSONL, promptfoo JSON) | the org's own model endpoint key, local only | Low, rising | S to parse, M to run | P3 (SPEC 0.8 names Garak) |
| 18 | GRC platform exports: Vanta, Drata, Secureframe | many slots via their control ids | third_party_attestation at most; subject_claim for manually uploaded evidence. Never Observed: the collector did not see the systems | export file or API | read-only auditor or viewer seat | Mid, high among SOC 2 seekers | M (control-id crosswalk per vendor) | P3 |
| 19 | Okta / Duo via API (API form of the built IdP export) | people-v1:mfa, least-privilege, jml | observed_export | API | Okta: `okta.users.read`, `okta.factors.read` (read-only admin); Duo Admin API "Grant read resource" | High | M | P3 (export file already covers it) |

## Skipped or deferred, and why

- Exposed-port checks (outside-in): skipped on purpose. A port scan of the internet-facing estate is the thing SPEC's non-goal describes, and it can trip the org's own IDS or a hosting provider's abuse policy. If a pilot wants it, the right source is the org's own scanner output (rank 8), sealed as Observed.
- Microsoft Graph, Google Admin SDK, GitHub API with a token, Splunk, EDR APIs, cloud APIs: not built today because they cannot be tested honestly without someone's tenant and credentials. They are ranks 1, 3, 5, 6, 7, 9 above; recorded fixtures from a pilot's sandbox tenant are the path.
- HR JML cross-check: easy in code, but the join key (work email, personal email, employee id) is a design decision the first pilot's data should make. Rank 2.
- Garak / promptfoo report parsers: easy to parse, but every item would land in `unmapped` until ai-cogsec slots exist in the evidence map, and the report formats have changed across releases. Deferred to the map decision.
- OSCAL XML/YAML: out of scope (JSON only, stdlib only); convert first.

## Gaps found while building (schema, rubric, scorer map)

1. No evidence-map slot, though the rubric has a home: security-awareness training and phishing simulation (people-v1/4b, 5b, 4c); disk encryption (technology-v1/3a); maintainer health (technology-v1/1x); dependency update tooling (technology-v1/1c); FIM (technology-v1/5a); offboarding integrity (people-v1/6c); every ai-cogsec-v1 key. Adapters emit these as `unmapped`.
2. No rubric home at all: email domain authentication (SPF, DMARC); `process-v1:incident-response` (known since 09-12; PagerDuty/Opsgenie would add to it).
3. Map rules exist only for attestations on many slots. `data-v1:in-transit`, `technology-v1:2.2a`, 4.4b, 4.4c, 6.6a, 6.6c and `process-v1:change-management` use `attested_present`, so Observed evidence there (the live TLS facts, the AWS key ages) scores nothing today. Measured: the outside-in package for valuechainrisk.org scores "no scorable evidence". These slots need observed-class rules.
4. `attested_present` levels any relayed third-party result at 2 whatever it says. Measured live: OpenSSF Scorecard for ossf/scorecard reports Vulnerabilities 0/10, and the scorer gives technology-v1 4a level 2 "attestation present". An OSCAL "not-satisfied" finding does the same. FIXED 2026-09-30 (Cairn): `attested_present` now returns no credit when an OSCAL result has not-satisfied findings or a Scorecard check scores 0/10; regression checks in test_score.py. Partial scores (1 to 9) still earn the attested level; whether they should scale is a methodology call for Joshua.
5. Existing bug, not fixed here (existing behavior): `exportmode.py` emits the observation key `least-privilege`, while the map reads `least_privilege.privileged_fraction`, so `people-v1:least-privilege` from the IdP export is never scored (checked on a sample package: only 2a and 2b score). The Entra CSV source mirrors the existing key so a single map fix covers both. FIXED 2026-09-30 (Cairn): map path changed to `least-privilege.privileged_fraction`; regression check in test_score.py.
6. Evidence classes missing from the schema: a Recorded class (named in the runtime observation spec, not defined in the schema or map); a class for third-party automated observation (Scorecard, a cloud provider's findings) distinct from an auditor's attestation; an assessor-observed class for OSCAL findings whose method is TEST. Today these ride as `third_party_attestation` with `source.kind` and per-finding `methods` and `origin_actor_types` kept so nothing is lost.
7. No adverse polarity in the schema. A POA&M item is evidence of an open gap; `oscalmode.py` marks it `polarity: open_gap`, but `report.py` counts any present item as Stated coverage, so a POA&M-only package would read as coverage in the framework report. Needs a schema field the report honors.
8. `unmapped` is an adapter convention (`subcriterion: "unmapped"` plus `mapping`), not yet part of the schema. Propose it for the v1 freeze.
9. Slot id spelling vs rubric keys (known since 09-12) still stands; new adapters use the existing slot ids.

## Provisional: third-party score bands (2026-09-30, Joshua's call: "bands, make it simple, keep an eye on where they should be")

Scorecard-style 0-10 check scores on one slot are averaged over conclusive checks: 8 or above earns the full attested level, 4 to 7.9 earns one level less, below 4 earns nothing, and any check at 0 earns nothing. The cut points live in `scorer-evidence-map-v0.json` (`attested_score_bands`), so moving them is a data change, not a code change.

Where the bands should really sit (open questions, revisit at the first pilot or after 10 scored packages, whichever comes first):
- Scorecard checks are not equally hard. Maintained and License are often 10; Code-Review, Branch-Protection and Signed-Releases are often low even on healthy projects. One cut point for all checks is too crude; per-check cut points from the public distribution are the likely end state.
- Anchor the cuts to a population, not a guess: OpenSSF publishes weekly Scorecard results for about a million repositories (public BigQuery dataset). The bands should mean something like "better than most projects" and "typical", expressed as percentiles.
- Solo-maintainer projects score low on review checks by construction; do not let that read as negligence without context.
- Averaging lets one strong check hide a weak one. If pilots show that, switch to "weakest conclusive check sets the band".
