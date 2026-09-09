"""Multi-anchor publication for sealed evidence packages.

Joshua's call, 2026-08-24: anchoring is not a pick-one. We publish to several
independent trust domains at once so that no single operator has to be trusted
and verification survives any one of them being discontinued.

The set, chosen for disjoint failure modes rather than redundancy:

  rfc3161        per package, synchronous. A signed wall-clock attestation from
                 an independent timestamp authority. The only anchor a court
                 already knows how to handle, verifiable with stock openssl.
  rekor-v2       per epoch. A real transparency log whose checkpoints are
                 co-signed by independent witnesses, so log equivocation is
                 detectable by parties with no relationship to us.
  opentimestamps per epoch. After upgrade, depends on nothing but Bitcoin block
                 headers: no company, no project, no server.

An adversary rewriting our history would have to compromise a witnessed
transparency log, rewrite proof-of-work, and forge a TSA key simultaneously.

Certificate Transparency is deliberately excluded. Smuggling hashes into CT via
issued certificates abuses a system scoped narrowly on purpose, and an examiner
who notices will use it against our credibility, correctly.

Two invariants everything here is built around:

  1. Anchoring NEVER blocks sealing. Sealing is local and must always succeed;
     anchoring is asynchronous, retryable, and allowed to fail.
  2. An unanchored package must never look anchored. State is recorded honestly
     and permanently, including "we tried and gave up". A record that overstates
     its own anchoring is worse than one admitting a gap, because it teaches a
     reader that our state fields cannot be trusted.
"""

import base64
import datetime
import glob
import hashlib
import json
import os
import re
import subprocess

H = os.path.expanduser

TRUST_DIR = H("~/.beacon/anchor-trust")
ANCHOR_DIR = H("~/.beacon/agent/anchors")
QUEUE_PATH = os.path.join(ANCHOR_DIR, "queue.json")

TSA_URL = "https://freetsa.org/tsr"
TSA_NAME = "freetsa.org"
REKOR_URL = "https://log2025-1.rekor.sigstore.dev/api/v2/log/entries"
REKOR_LOG = "log2025-1.rekor.sigstore.dev"

# Rekor entries are PERMANENT, PUBLIC, and carry our collector's public key,
# which makes the household's signing identity publicly linkable forever. That
# is a one-way door, so it stays off until the operator turns it on explicitly.
REKOR_ENABLED_FLAG = H("~/.beacon/anchor-trust/REKOR-ENABLED")

RETRY_SCHEDULE = [60, 120, 240, 480, 960, 1920, 3840, 7680, 21600]
ABANDON_AFTER_SECONDS = 7 * 24 * 3600

STATES = ("pending", "submitted", "confirmed", "failed")


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------- merkle
# RFC 6962 domain separation, so any CT-literate tool can check our paths.


def _leaf(h):
    return hashlib.sha256(b"\x00" + h).digest()


def _node(l, r):
    return hashlib.sha256(b"\x01" + l + r).digest()


def merkle_root_and_paths(pkg_hashes):
    """Returns (root, {leaf_index: audit_path}) over raw 32-byte digests."""
    if not pkg_hashes:
        return None, {}
    level = [_leaf(h) for h in pkg_hashes]
    paths = {i: [] for i in range(len(level))}
    pos = {i: i for i in range(len(level))}
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                for leaf_i, p in pos.items():
                    if p == i:
                        paths[leaf_i].append(["R", level[i + 1].hex()])
                    elif p == i + 1:
                        paths[leaf_i].append(["L", level[i].hex()])
                nxt.append(_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # odd node promoted with no sibling
        pos = {k: v // 2 for k, v in pos.items()}
        level = nxt
    return level[0], paths


def epoch_commitment(epoch_id, tree_root, prev_anchored_root):
    """The value actually anchored for an epoch.

    Commits to the epoch number, its Merkle tree (or emptiness), and the
    previous epoch's anchored root. Chaining epochs means a removed epoch breaks
    the chain rather than merely leaving a gap in the numbering, and anchoring
    empty epochs keeps the stream continuous so that silence is a positive
    signal instead of an ambiguity someone can argue about later.
    """
    h = hashlib.sha256()
    h.update(b"beacon-epoch-v1|")
    h.update(str(epoch_id).encode() + b"|")
    h.update((tree_root.hex() if tree_root else "EMPTY").encode() + b"|")
    h.update((prev_anchored_root or "GENESIS").encode())
    return h.digest()


def verify_path(pkg_hash, path, root):
    cur = _leaf(pkg_hash)
    for side, sib in path:
        sib = bytes.fromhex(sib)
        cur = _node(sib, cur) if side == "L" else _node(cur, sib)
    return cur == root


# ---------------------------------------------------------------- rfc 3161


def tsa_timestamp(data_bytes, url=TSA_URL, timeout=30):
    """Signed time attestation over the package bytes themselves.

    Timestamping the artifact rather than a digest-of-a-digest keeps the
    verification command the one an examiner already knows:
      openssl ts -verify -in pkg.tsr -data package.json -CAfile ... -untrusted ...
    """
    import httpx
    from rfc3161_client import TimestampRequestBuilder, decode_timestamp_response
    from rfc3161_client.base import HashAlgorithm

    # SHA-256 to match the rest of the chain; the client would otherwise default
    # to SHA-512, which works but makes the imprint algorithm inconsistent with
    # every other hash in the evidence.
    req = (TimestampRequestBuilder()
           .data(data_bytes)
           .hash_algorithm(HashAlgorithm.SHA256)
           .nonce(nonce=True)
           .build())
    r = httpx.post(url, content=req.as_bytes(),
                   headers={"Content-Type": "application/timestamp-query"},
                   timeout=timeout)
    r.raise_for_status()
    resp = decode_timestamp_response(r.content)
    ti = resp.tst_info
    return r.content, {
        "kind": "rfc3161",
        "authority": TSA_NAME,
        "state": "confirmed",
        "observed_time": ti.gen_time.isoformat(),
        "serial": hex(ti.serial_number),
        "trust_anchor": "freetsa-cacert.pem",
        "trust_anchor_sha256": _file_sha(os.path.join(TRUST_DIR, "freetsa-cacert.pem")),
        "verify_hint": ("openssl ts -verify -in <pkg>.tsr -data package.json "
                        "-CAfile freetsa-cacert.pem -untrusted freetsa-tsa.crt"),
    }


def _file_sha(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


# ---------------------------------------------------------------- opentimestamps


def ots_stamp(root_file, timeout=180):
    """Submit to the OTS calendars. Result is PENDING, not yet Bitcoin-backed."""
    ots = _ots_bin()
    r = subprocess.run([ots, "stamp", root_file], capture_output=True,
                       text=True, timeout=timeout)
    proof = root_file + ".ots"
    if r.returncode != 0 or not os.path.isfile(proof):
        return None, {"kind": "opentimestamps", "authority": "bitcoin",
                      "state": "pending", "error": (r.stderr or "").strip()[:300],
                      "submitted": utcnow()}
    return proof, {
        "kind": "opentimestamps",
        "authority": "bitcoin",
        # Deliberately not "confirmed": a fresh .ots only points back at the
        # calendars. It is not self-contained until upgrade pulls down the path
        # to a Bitcoin block. Calling this confirmed would be the exact kind of
        # overstatement invariant 2 forbids.
        "state": "submitted",
        "substate": "pending_upgrade",
        "submitted": utcnow(),
        "artifact": os.path.basename(proof),
        "note": "not self-contained until 'ots upgrade' completes; run the upgrade job",
    }


def ots_upgrade(proof_file, timeout=180):
    """Pull the completed Bitcoin path down. Idempotent; safe to re-run."""
    ots = _ots_bin()
    subprocess.run([ots, "upgrade", proof_file], capture_output=True,
                   text=True, timeout=timeout)
    v = subprocess.run([ots, "--no-bitcoin", "verify", proof_file],
                       capture_output=True, text=True, timeout=timeout)
    blob = (v.stdout or "") + (v.stderr or "")

    # Do NOT substring-match "Bitcoin block": the pending message reads
    # "Pending confirmation in Bitcoin blockchain" and contains it. Confirmation
    # requires a real attestation AND no outstanding pending calendar entries.
    pending = "Pending confirmation" in blob or "PendingAttestation" in blob

    # Two phrasings, because the client says a different thing in each mode:
    #   with a node reachable : "Bitcoin block N attests existence as of ..."
    #   with --no-bitcoin     : "To verify manually, check that Bitcoin block N
    #                            has merkleroot ..."
    # We run --no-bitcoin deliberately (an anchor job must never depend on a
    # local Bitcoin node), so the SECOND form is the one we actually see. Only
    # matching the first made every completed upgrade read as still-pending —
    # epochs 1..40 held real BitcoinBlockHeaderAttestations and were reported
    # stuck for two days. Found 2026-08-26.
    attested = re.search(r"Bitcoin block (\d+) attests", blob) or \
        re.search(r"attests existence as of", blob) or \
        re.search(r"check that Bitcoin block (\d+) has merkleroot", blob)

    if attested and not pending:
        m = re.search(r"Bitcoin block (\d+)", blob)
        # Honesty about WHAT was checked: --no-bitcoin means the block height
        # was read out of the proof's own attestation, not validated against
        # the chain. The proof is self-contained (that is what this state
        # claims); it has not been independently confirmed against a node.
        node_checked = "Bitcoin disabled" not in blob
        return True, {"state": "confirmed",
                      "bitcoin_block": int(m.group(1)) if m else None,
                      "attestation_source": "proof" if not node_checked else "node",
                      "verified_against_chain": node_checked,
                      "upgraded": utcnow(), "verify_output": blob.strip()[:400]}
    return False, {"state": "submitted", "substate": "pending_upgrade",
                   "last_checked": utcnow(),
                   "calendars_pending": blob.count("Pending confirmation"),
                   "verify_output": blob.strip()[:400]}


def _ots_bin():
    local = H("~/.beacon/venv/bin/ots")
    return local if os.path.isfile(local) else "ots"


# ---------------------------------------------------------------- rekor v2


def rekor_enabled():
    return os.path.isfile(REKOR_ENABLED_FLAG)


def rekor_submit(root_digest, signature, pub_der, timeout=45):
    """Publish an epoch root to the public transparency log.

    Guarded: writing here is permanent and public and binds our signing key to
    the record forever. The gate is a file the operator creates, not a default.
    """
    if not rekor_enabled():
        return None, {"kind": "rekor-v2", "authority": REKOR_LOG, "state": "pending",
                      "reason": "rekor publication not enabled on this collector; "
                                "create %s to enable" % REKOR_ENABLED_FLAG}
    import httpx
    body = {"hashedRekordRequestV002": {
        "digest": base64.b64encode(root_digest).decode(),
        "signature": {
            "content": base64.b64encode(signature).decode(),
            "verifier": {"publicKey": {"rawBytes": base64.b64encode(pub_der).decode()},
                         "keyDetails": "PKIX_ED25519"}}}}
    r = httpx.post(REKOR_URL, json=body, timeout=timeout)
    if r.status_code >= 400:
        return None, {"kind": "rekor-v2", "authority": REKOR_LOG, "state": "pending",
                      "http_status": r.status_code, "error": r.text[:300],
                      "last_attempt": utcnow()}
    entry = r.json()
    proof = entry.get("inclusionProof", {}) or {}
    return entry, {
        "kind": "rekor-v2",
        "authority": REKOR_LOG,
        "state": "confirmed",
        "log_index": entry.get("logIndex"),
        "tree_size": proof.get("treeSize"),
        "has_checkpoint": bool(proof.get("checkpoint")),
        "submitted": utcnow(),
        "note": "integratedTime is always 0 in Rekor v2; time comes from the checkpoint",
    }


# ---------------------------------------------------------------- queue


def load_queue():
    try:
        with open(QUEUE_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"epochs": {}}


def save_queue(q):
    os.makedirs(ANCHOR_DIR, exist_ok=True)
    tmp = QUEUE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(q, f, indent=2)
    os.replace(tmp, QUEUE_PATH)


def due(entry, now_epoch):
    """Exponential backoff with a hard abandon horizon."""
    attempts = entry.get("attempts", 0)
    first = entry.get("first_attempt_epoch") or now_epoch
    if now_epoch - first > ABANDON_AFTER_SECONDS:
        return False
    if attempts == 0:
        return True
    wait = RETRY_SCHEDULE[min(attempts - 1, len(RETRY_SCHEDULE) - 1)]
    return now_epoch - entry.get("last_attempt_epoch", 0) >= wait
