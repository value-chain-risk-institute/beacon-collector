"""
pairing.py: H22, the action-pairing delta. DERIVED: deterministic set arithmetic
over records already sealed in H18 (and later H19 to H21), recomputable by any
verifier from those items. It never says "suspicious"; it says which records one
source has that another lacks, joined on vendor ids, and how many.

v0.3 pairs the two claim sources on one endpoint: the hook (written as the agent
acts) and the transcript (written by the harness). Two claim sources do not make
an observation, and the output says so.
"""


def _ids(records, source, event):
    return {r.get("correlation", {}).get("tool_use_id") for r in records
            if r.get("source") == source and r.get("event") == event
            and r.get("correlation", {}).get("tool_use_id")}


def _commit_by_id(records, source, event, field):
    out = {}
    for r in records:
        if r.get("source") == source and r.get("event") == event:
            tid = r.get("correlation", {}).get("tool_use_id")
            if tid:
                out[tid] = r.get("content_commitments", {}).get(field)
    return out


def pair(records, hook_present):
    """records: every H18 record sealed in this package (both sources)."""
    if not hook_present:
        return {"pairing": {"present": False,
                            "note": "one claim source only (transcript); the hook is not "
                                    "installed, so there is nothing to pair it against. "
                                    "Absence of a pair is not agreement."},
                "derived": True}
    hook_calls = _ids(records, "claude-code-hook", "tool_call")
    tx_calls = _ids(records, "claude-code-transcript", "tool_call")
    hook_in = _commit_by_id(records, "claude-code-hook", "tool_call", "tool_input")
    tx_in = _commit_by_id(records, "claude-code-transcript", "tool_call", "tool_input")
    both = hook_calls & tx_calls
    input_mismatch = sorted(t for t in both
                            if hook_in.get(t) and tx_in.get(t) and hook_in[t] != tx_in[t])
    return {"pairing": {
                "present": True,
                "sides": ["claim:claude-code-hook", "claim:claude-code-transcript"],
                "tool_calls_hook": len(hook_calls),
                "tool_calls_transcript": len(tx_calls),
                "in_both": len(both),
                "hook_not_transcript": sorted(hook_calls - tx_calls),
                "transcript_not_hook": sorted(tx_calls - hook_calls),
                "input_commitment_differs": input_mismatch,
                "window_note": "a call near a tick boundary can land in adjacent packages; "
                               "read unmatched ids across the neighbouring seal before "
                               "treating them as unmatched",
                "grade": "two claim sources; agreement here is consistency, not observation"},
            "derived": True,
            "recompute": "from the H18 segment blob of this package"}
