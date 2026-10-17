# Crosswalks: framework clause -> VCRI rubric subcriterion (DRAFT)

A crosswalk lets a confirmed policy mapping reach the scorer. The document ingester
seals each confirmed mapping on a crosswalked clause a second time, on the evidence-map
slot of the target subcriterion, as stated-class evidence (`epistemic: subject_claim`).
`score.py` scores it at `stated_present_level` (1), under the stated cap (1), and only
when `human_confirmed` is true. A target with no slot in `scorer-evidence-map-v0.json`
is sealed as `unmapped` and reported as a gap.

Both files here are DRAFT methodology proposals with a handful of entries each, written
to exercise the path. They are not crosswalks of CIS v8.1 or SP 800-171 and have not
been ratified. Which clause routes where is VCRI's decision, recorded in its change log.

Format (`vcri.beacon.crosswalk/v0`):

```
{ "_schema": "vcri.beacon.crosswalk/v0",
  "id": "...", "version": "...", "status": "draft-unratified" | "ratified",
  "framework": {"ids": ["<framework id the clause ids belong to>", ...]},
  "entries": [ {"clause_id": "6.3", "targets": [{"rubric": "people-v1", "key": "2a"}], "rationale": "..."} ] }
```

The ingester refuses a crosswalk whose framework ids do not include the catalog in use,
or whose clause ids are not in that catalog. The crosswalk's sha256 is sealed with every
item it routes.
