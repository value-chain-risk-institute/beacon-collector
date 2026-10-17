# Beacon Collector: Document Ingester — simple design v0.1

Joshua Marpet and Cairn Viktor. 8 October 2026. For sign-off before any code. Design goal: the simplest thing that works, true to "the Collector packages, it never judges."

## What it does, in one sentence

You feed the Collector a policy document, pick a framework, and it points each framework clause at the exact piece of your policy that addresses it, then seals those pointers as checkable evidence, after a human confirms them.

## The flow

1. User tells the Collector: "ingest these documents and map them to a framework."
2. User feeds one or more documents (PDF, DOCX, Markdown, text) and clicks map.
3. User picks the framework from a selector: CIS v8.1, PCI DSS, NIST CSF 2.0, HIPAA / HHS HICP, CRI Profile, and whatever else VCRI has published.
4. The Collector fetches that one framework from VCRI as a machine-readable file (OSCAL catalog, or CSAF where that fits) on demand. It does not carry every framework around; VCRI is the framework library, the Collector pulls only what you picked.
5. For each clause in the framework, the Collector proposes the best-matching excerpt(s) from your documents, with a confidence and the quoted span and its location (doc + page/section).
6. A human reviews the proposals in a thin local page: confirm, correct the span, or mark "not covered." Only confirmed mappings enter the package. No-match and low-confidence clauses are flagged as gaps, which is itself useful evidence.
7. The Collector seals the confirmed mappings into the normal evidence package (Merkle-sealed, owned by you, nothing leaves the box).

## Modularity (Joshua's point)

The framework is data, fetched at run time, not code baked into the Collector. Every framework VCRI publishes as OSCAL/CSAF instantly becomes something the Collector can map against, with no new release. VCRI hosts the catalog; the Collector requests `framework/<id>/<version>.oscal.json`, records its hash, and maps against it.

## Evidence class (agreed)

An AI-proposed mapping is stated-class evidence (level 1). Human confirmation does not make it higher-class on its own, a policy is still an assertion, but the sealed, verbatim excerpt plus the framework hash plus who-confirmed-and-when make the pointer checkable: a reviewer can open the package and see exactly which sentence was mapped to which clause. The Collector still renders no judgment; it packages a confirmed pointer. Scoring that pointer stays in the scorer / CRC layer.

## The new evidence item (shape)

```
{ "type": "document-mapping",
  "framework": {"id": "cis-8.1", "version": "...", "oscal_sha256": "..."},
  "clause_id": "8.2",
  "source_doc": {"name": "InfoSec-Policy.pdf", "sha256": "..."},
  "excerpt": {"text": "<verbatim span>", "location": "p.11, section 4.3"},
  "confidence": 0.82,
  "mapper": {"model": "...", "version": "...", "run_at": "..."},
  "human": {"confirmed": true, "by": "jdoe", "at": "..."} }
```

## The matcher (keep it simple for v1)

- Chunk the document, embed the chunks and the clause text, take the top candidate spans by semantic similarity, then one LLM pass to pick the best verbatim span and a confidence. Model is swappable and can run through the existing inference proxy; nothing about the document leaves the box.
- Guardrails: the excerpt is quoted verbatim, never paraphrased, so the reviewer sees exactly what was matched; a confidence floor routes weak matches to the gap list rather than asserting them; the human-confirm step is mandatory before anything is sealed.

## The UI (the only screen)

One local page the Collector opens when there are mappings to confirm: a list of clause → proposed excerpt rows with confidence, three buttons each (confirm / edit span / not covered), a framework picker at the top, and a "seal package" button at the bottom. That is the whole interface. It exists because an autonomous AI mapping needs a human to confirm it; it is not a general console.

## What is reused vs new

- Reused: the Collector's packaging/sealing (Merkle), the evidence-package format, the inference proxy, and VCRI's already-published framework content (CIS map, rubrics).
- New: the OSCAL/CSAF fetch, the matcher, the `document-mapping` evidence type, and the one confirm page.

## Decisions (Joshua, 2026-10-09)

1. Frameworks first, as OSCAL on VCRI: CIS v8.1, NIST CSF 2.0, HIPAA / HHS HICP, EU CRA. (CIS v8.1 and NIST CSF 2.0 have official OSCAL; HICP and EU CRA we author as OSCAL catalogs.)
2. Matching: the open VCRI Collector is local-only (nothing about a policy document leaves the box). The paid CRC path may add cloud inference for higher-quality matching on authorized documents. So the matcher is pluggable: a local backend by default, a cloud backend only in the CRC build.
3. Review: the open VCRI Collector is single-reviewer confirm. CRC adds the richer options (second reviewer co-sign, reviewer roles) for rating-grade packages.

### The VCRI / CRC split this creates

| Capability | VCRI Collector (open, free) | CRC (paid) |
|---|---|---|
| Matching | local-only backend | may use cloud inference |
| Review / confirm | single reviewer | co-sign, reviewer roles |
| Output | sealed evidence package you own | independently re-verified rating |

The open Collector stays simple and private; CRC's compute and rigor are the paid differentiators. Same evidence-package format throughout.
