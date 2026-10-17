# Document ingester: quick start (v0.2, 2026-10-16)

Point a framework's clauses at the sentences in your policy that address them, confirm
each pointer yourself, and seal the confirmed pointers as evidence you own. The Collector
proposes and packages. It never judges or scores the policy, and nothing about your
documents leaves your machine. Design: `DESIGN-document-ingester-v0.1-Marpet-Viktor.md`.

## Install

```
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt               # sealing, signing, anchoring
pip install -r requirements-optional.txt      # only if you ingest .pdf (pypdf)
```

.md, .txt and .docx need nothing beyond the standard library. Without pypdf a .pdf is
refused with a message saying how to fix it (or export the policy as .docx).

## Pick a framework

```
python ingestmode.py frameworks
```

| id | what | where it comes from |
|---|---|---|
| `nist-csf-2.0` | NIST CSF 2.0, 106 subcategories | vendored in `catalogs/` |
| `nist-sp800-171r3` | NIST SP 800-171 Rev 3, 97 requirements | vendored in `catalogs/` |
| `cis-8.1` | CIS Controls v8.1, 153 safeguards | downloaded from CIS on first use, hash-checked, cached in `~/.beacon/catalogs/` |

`--framework` also takes an https URL to any OSCAL catalog JSON, or a local file (OSCAL,
or the simple `{id, version, clauses: [{id, title, text}]}` format). Add
`--framework-sha256 <hash>` to pin the bytes. Provenance and licenses: `catalogs/SOURCE.md`.

## Review and seal (the normal path)

```
python ingestmode.py review \
    --doc InfoSec-Policy.docx --doc Backup-Standard.md \
    --framework cis-8.1 \
    --subject "Your Org" --out-dir out-ingest
```

The confirm page opens in your browser (`--no-browser` prints the URL instead). It is
served on 127.0.0.1 only, behind a one-time token in the URL, and it closes when you seal.
For each clause you see the proposed excerpt, exactly as it appears in your document,
where it is (document, page or section heading, paragraph number), and a confidence:

- Confirm: the excerpt addresses the clause. Sealed as `human.confirmed: true`, with your name and the time.
- Edit span: narrow or replace the excerpt. The text must be your document's exact words; anything else is refused. "Other candidates" offers the next-best paragraphs.
- Not covered: sealed as a recorded gap.
- Rows you leave alone are sealed as unconfirmed proposals. Clauses below the confidence floor (`--floor`, default 0.2) start as gaps; you can still supply a span for them.

Type your name and press Seal package. Then:

```
python ingestmode.py verify out-ingest/package.json
python score.py out-ingest/package.json        # only if you used --crosswalk; see below
```

## Without review

`python ingestmode.py collect ...` (same options) seals every proposal unconfirmed, as v0.1
did. Useful to see what the matcher finds; not rating-grade.

## What gets sealed

- One `document_mapping` item per document (the document itself is the sealed blob): every mapping with its verbatim excerpt, location, confidence, matcher, and `human` (confirmed, by, at, decision).
- One `document_mapping_summary` item over a sealed review record (what was proposed, what you decided): counts and the gaps list.
- With `--crosswalk`, one `stated` item per rubric subcriterion your confirmed mappings route to.

Every item records the framework catalog's sha256. All items are Stated class
(`epistemic: subject_claim`): a policy is your declaration. The seal proves the excerpt is
a verbatim span of the sealed document and who confirmed it, not that the policy is
followed.

## Crosswalk to the scorer (optional, DRAFT)

```
--crosswalk crosswalks/DRAFT-cis-8.1-to-vcri-rubrics.json
--crosswalk crosswalks/DRAFT-nist-sp800-171r3-to-vcri-rubrics.json
```

A crosswalk maps framework clauses to VCRI rubric subcriteria. Confirmed mappings on
crosswalked clauses then score in `score.py` at level 1 (stated evidence is capped at 1);
unconfirmed ones never score. The two files shipped are small, unratified methodology
proposals for VCRI, not crosswalks of either framework. See `crosswalks/README.md`.

## Limits (v0.2)

- The matcher is local BM25 with crude stemming: it finds shared vocabulary, not meaning. Expect wrong proposals; that is what review is for. The backend interface (`ingestlib.MatcherBackend`) is where an embedding or LLM matcher would go; the open build refuses any backend that declares network access.
- If the same sentence appears twice, an edited span is located at its first occurrence.
- .docx has no fixed pages, so its locations are section heading + paragraph (non-empty paragraphs in document order, headings and table cells included, starting at 1). PDF locations are page + paragraph on that page. Scanned PDFs need OCR first.
- Single reviewer. Co-sign and reviewer roles are CRC features.
