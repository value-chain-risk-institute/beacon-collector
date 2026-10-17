# Framework catalogs: provenance

Every catalog the ingester maps against is pinned by sha256 in `index.json`. A file
whose bytes differ from its pin is refused. Verified and fetched by Cairn Viktor on
2026-10-17 02:36 UTC (2026-10-16 evening, US time). Re-pin deliberately when a
publisher updates a file, and add a dated line here.

## Vendored (in this directory)

### NIST Cybersecurity Framework 2.0

- File: `nist-csf-2.0.oscal.json` (OSCAL catalog, minified; document version 1.2.0, last-modified 2026-05-11, OSCAL 1.2.2)
- Source: usnistgov/oscal-content, commit `78650f02ad9321bb7b817846f8fbd4f2bcd620de` (2026-05-13), path `nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog-min.json`
- URL: https://raw.githubusercontent.com/usnistgov/oscal-content/78650f02ad9321bb7b817846f8fbd4f2bcd620de/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog-min.json
- sha256: `87d31e856ab2d2b5fb78d66233cc257a2e1a6c3c51b367ab73c10124b25adc3b`
- License: US Government work, public domain in the US; worldwide CC0 1.0 waiver (oscal-content LICENSE.md).
- Normalized: 106 subcategories (the leaf clauses). The 91 entries marked `status: withdrawn` (CSF 1.1 subcategories carried for reference) are skipped; functions and categories are parents, not clauses.

### NIST SP 800-171 Revision 3

- File: `nist-sp800-171r3.oscal.json` (OSCAL catalog, minified; document version 1.1.0, last-modified 2026-05-12, OSCAL 1.2.2)
- Source: usnistgov/oscal-content, same commit, path `nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog-min.json`
- URL: https://raw.githubusercontent.com/usnistgov/oscal-content/78650f02ad9321bb7b817846f8fbd4f2bcd620de/nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog-min.json
- sha256: `940a3f6bb5bcf8e656aa673f071c1677ae45a3cd6bd7be62e8edc874d2410a2f`
- License: as above (public domain / CC0).
- Normalized: 97 requirements (33 withdrawn entries skipped). Organization-defined parameters are rendered as `[Assignment: ...]`; guidance and assessment objectives are not clause text.

### Sample (tests only)

- File: `cis-8.1-sample.json`, id `cis-8.1-sample`. Hand-written five-clause subset in the simple format for the v0.1 tests. Titles follow CIS safeguard names; the statement wording is paraphrased. It is not the CIS catalog and must not be used for a real mapping.

## Fetched at run time (verified, NOT vendored)

### CIS Critical Security Controls v8.1

- Official OSCAL exists, published by CIS (not on GitHub any more: the GitHub repo CISecurity/CISControls_OSCAL is archived and points to Bitbucket).
- Repo: https://bitbucket.org/cis-it-workspace/cis-controls-v8.1_oscal, commit `c97fa0838bb20c435499ab2575e1410f5d304212` (2026-06-25)
- URL (pinned): https://bitbucket.org/cis-it-workspace/cis-controls-v8.1_oscal/raw/c97fa0838bb20c435499ab2575e1410f5d304212/src/catalogs/json/cis-controls-v8.1_catalog.json
- sha256: `577aa09d242fa03470af47f32c8ecd6de89318c48452911183d2ce863b486182` (catalog metadata version 8.1.2, last-modified 2025-04-09, OSCAL 1.1.3)
- Normalized by `ingestlib.load_framework`: 153 safeguards, ids from the label (`CIS Safeguard 1.1` -> `1.1`).
- Why not vendored: the repo's LICENSE.md is the CIS Terms of Use for Non-Member CIS Products (CIS Controls under CC BY-NC-ND 4.0; the terms forbid posting the product on any website and creating derivative works). Committing it to an Apache-2.0 repo that may be published is redistribution. The Collector instead downloads it from CIS on the user's machine, checks the pin, and caches it under `<home>/catalogs/`. VCRI should ask CIS before hosting it.

## Not available as official OSCAL (checked 2026-10-16)

- NIST SP 800-171 Revision 2: not in usnistgov/oscal-content (only Rev 3 is), and the CSRC publication page for Rev 2 links no OSCAL or CPRT export. Not fabricated here. If a Rev 2 mapping is needed (CMMC 2.0 Level 2 still cites Rev 2), it would have to be authored by VCRI as an OSCAL catalog and labeled as VCRI-authored.
- HIPAA / HHS HICP and the EU CRA: no official OSCAL; per the 2026-10-09 decisions VCRI authors those. Not started in this branch.
