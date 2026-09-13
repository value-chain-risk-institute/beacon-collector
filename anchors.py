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

def _resolve_trust_dir():
    """Where the TSA trust chain lives. Operator override first, then the
    per-machine home, then the copy shipped in the repo so a fresh org install
    can verify tokens without a separate download step."""
    env = os.environ.get("BEACON_TRUST_DIR")
    if env:
        return H(env)
    home = H("~/.beacon/anchor-trust")
    if os.path.isfile(os.path.join(home, "freetsa-cacert.pem")):
        return home
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "anchor-trust")


TRUST_DIR = _resolve_trust_dir()
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


# ---------------------------------------------------------------- per-package
# One implementation of "anchor this sealed package", shared by agent mode and
# by the org modes (scanner, document, export, merge). Added 2026-09-12: until
# then only agent mode anchored anything, and org packages carried a literal
# stub in seal.anchor while the README said "sealed and anchored".
#
# Same two invariants as the top of this file: sealing has already happened by
# the time this runs and is never undone by an anchoring failure; and the
# sidecar record says exactly what was and was not obtained.


def _load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def record_path(pkg_path):
    return pkg_path + ".anchors.json"


LATE_ANCHOR_TOLERANCE_SECONDS = 60


def _seconds_between(earlier_iso, later_iso):
    """Signed seconds from earlier to later; None if either stamp is unparseable.
    Naive stamps are read as UTC, which is what every writer in this tree emits."""
    try:
        a = datetime.datetime.fromisoformat(earlier_iso.replace("Z", "+00:00"))
        b = datetime.datetime.fromisoformat(later_iso.replace("Z", "+00:00"))
        if a.tzinfo is None:
            a = a.replace(tzinfo=datetime.timezone.utc)
        if b.tzinfo is None:
            b = b.replace(tzinfo=datetime.timezone.utc)
        return round((b - a).total_seconds(), 3)
    except (ValueError, AttributeError, TypeError):
        return None


def rfc3161_anchor_file(pkg_path, sealed_utc=None, timeout=30):
    """Timestamp the package bytes with the TSA. Returns (token_bytes|None, meta).
    A token taken after sealing is recorded as late_anchor rather than allowed
    to disagree quietly with the seal time."""
    with open(pkg_path, "rb") as f:
        body = f.read()
    try:
        token, meta = tsa_timestamp(body, timeout=timeout)
    except Exception as e:
        return None, {"kind": "rfc3161", "authority": TSA_NAME, "state": "pending",
                      "error": "%s: %s" % (type(e).__name__, str(e)[:160]),
                      "last_attempt": utcnow()}
    # How long after sealing was the token taken? At-write anchoring lands within
    # a second or two and is recorded as such; a token taken later than
    # LATE_ANCHOR_TOLERANCE_SECONDS (an hourly job, a manual retry) is flagged
    # late so the two timestamps never quietly disagree.
    if sealed_utc:
        delta = _seconds_between(sealed_utc, meta["observed_time"])
        meta["sealed_utc"] = sealed_utc
        meta["seconds_after_seal"] = delta
        if delta is not None and delta > LATE_ANCHOR_TOLERANCE_SECONDS:
            meta["late_anchor"] = True
            meta["note"] = ("token obtained after sealing; it attests when the anchor was "
                            "taken, not when the package was sealed")
    tsr_path = pkg_path + ".tsr"
    with open(tsr_path, "wb") as f:
        f.write(token)
    meta["artifact"] = os.path.basename(tsr_path)
    return token, meta


def _merge_anchor(rec, meta):
    rec["anchors"] = [a for a in rec.get("anchors", []) if a.get("kind") != meta["kind"]] + [meta]


def anchor_package(pkg_path, sealed_utc=None, home=None, do_ots=True, do_rekor=True,
                   tsa_timeout=30, ots_timeout=60):
    """Anchor one sealed org package in place. Writes <pkg>.tsr, <pkg>.ots and
    the sidecar <pkg>.anchors.json. Never raises on anchor failure; the record
    carries the failure. Returns the record."""
    pkg = _load_json(pkg_path) or {}
    package_hash = (pkg.get("seal") or {}).get("package_hash")
    rec = _load_json(record_path(pkg_path)) or {"package_hash": package_hash, "anchors": []}
    if package_hash and rec.get("package_hash") not in (None, package_hash):
        # The sidecar belongs to a different package body. Refuse to mix them.
        rec = {"package_hash": package_hash, "anchors": [],
               "note": "previous sidecar discarded: package_hash changed"}
    rec["package_hash"] = package_hash
    rec["anchored_by"] = "beacon anchors.anchor_package"
    rec["last_run"] = utcnow()

    # 1. RFC 3161, synchronous, the anchor a court already understands.
    if not os.path.isfile(pkg_path + ".tsr"):
        _, meta = rfc3161_anchor_file(pkg_path, sealed_utc, timeout=tsa_timeout)
        _merge_anchor(rec, meta)

    # 2. OpenTimestamps on the package file itself. For org packages we stamp
    #    per package rather than per epoch: an org seals a handful of packages,
    #    not one every fifteen minutes, and a per-file proof is what a third
    #    party can check with the stock `ots verify` command. The calendars
    #    aggregate on their side. Result is SUBMITTED until `upgrade` pulls the
    #    Bitcoin path down; see ots_stamp for why it is not called confirmed.
    if do_ots:
        existing = [a for a in rec["anchors"] if a.get("kind") == "opentimestamps"]
        if not os.path.isfile(pkg_path + ".ots") or not existing:
            try:
                _, meta = ots_stamp(pkg_path, timeout=ots_timeout)
            except Exception as e:
                meta = {"kind": "opentimestamps", "authority": "bitcoin", "state": "pending",
                        "error": "%s: %s" % (type(e).__name__, str(e)[:160]),
                        "last_attempt": utcnow()}
            _merge_anchor(rec, meta)

    # 3. Rekor. Gated by the operator flag exactly as in agent mode, and for org
    #    packages ALSO held until the digest/signature semantics of the v2
    #    hashedrekord entry have been exercised live (never has been: the flag
    #    has never been set). Recorded honestly as pending with the reason.
    if do_rekor:
        if not rekor_enabled():
            _merge_anchor(rec, {"kind": "rekor-v2", "authority": REKOR_LOG, "state": "pending",
                                "reason": "rekor publication not enabled on this collector; "
                                          "create %s to enable" % REKOR_ENABLED_FLAG})
        else:
            _merge_anchor(rec, {"kind": "rekor-v2", "authority": REKOR_LOG, "state": "pending",
                                "reason": "per-package rekor publication not yet implemented for "
                                          "org packages (2026-09-12); epoch publication lives in "
                                          "agent mode"})

    with open(record_path(pkg_path), "w") as f:
        json.dump(rec, f, indent=2)
    return rec


def upgrade_package_anchors(pkg_path, timeout=180):
    """Pull the Bitcoin path down for a per-package OTS proof; idempotent."""
    rec = _load_json(record_path(pkg_path))
    proof = pkg_path + ".ots"
    if not rec or not os.path.isfile(proof):
        return False, rec
    for a in rec.get("anchors", []):
        if a.get("kind") == "opentimestamps" and a.get("state") != "confirmed":
            ok, meta = ots_upgrade(proof, timeout=timeout)
            a.update(meta)
            with open(record_path(pkg_path), "w") as f:
                json.dump(rec, f, indent=2)
            return ok, rec
    return True, rec


def verify_package_anchors(pkg_path):
    """Offline check of whatever anchors exist for one package, the way a
    third party would do it later. Returns (ok, findings). A missing anchor
    is a finding, not a failure: 'unanchored' is a truthful state."""
    findings = []
    ok = True
    rec = _load_json(record_path(pkg_path))
    pkg = _load_json(pkg_path) or {}
    package_hash = (pkg.get("seal") or {}).get("package_hash")
    if rec is None:
        findings.append(("unanchored", "no sidecar record; package has never been anchored"))
        return ok, findings
    if package_hash and rec.get("package_hash") != package_hash:
        findings.append(("MISMATCH", "sidecar package_hash differs from the package's seal"))
        ok = False
    tsr = pkg_path + ".tsr"
    if os.path.isfile(tsr):
        r = subprocess.run(["openssl", "ts", "-verify", "-in", tsr, "-data", pkg_path,
                            "-CAfile", os.path.join(TRUST_DIR, "freetsa-cacert.pem"),
                            "-untrusted", os.path.join(TRUST_DIR, "freetsa-tsa.crt")],
                           capture_output=True, text=True)
        good = "Verification: OK" in (r.stdout + r.stderr)
        findings.append(("rfc3161", "token verifies offline against %s" % TRUST_DIR if good
                         else "TOKEN FAILED VERIFICATION: %s" % (r.stderr or r.stdout).strip()[:200]))
        ok = ok and good
    else:
        findings.append(("rfc3161", "no token on disk"))
    proof = pkg_path + ".ots"
    if os.path.isfile(proof):
        v = subprocess.run([_ots_bin(), "--no-bitcoin", "verify", proof],
                           capture_output=True, text=True)
        blob = (v.stdout or "") + (v.stderr or "")
        if re.search(r"Bitcoin block (\d+)", blob) and "Pending confirmation" not in blob:
            findings.append(("opentimestamps", "proof self-contained: %s" %
                             re.search(r"Bitcoin block \d+", blob).group(0)))
        elif "Pending confirmation" in blob:
            findings.append(("opentimestamps", "proof present, awaiting Bitcoin confirmation (run upgrade later)"))
        else:
            findings.append(("opentimestamps", "PROOF DID NOT VERIFY: %s" % blob.strip()[:200]))
            ok = False
    else:
        findings.append(("opentimestamps", "no proof on disk"))
    for a in rec.get("anchors", []):
        if a.get("kind") == "rekor-v2":
            findings.append(("rekor-v2", a.get("state") + (": " + a["reason"] if a.get("reason") else "")))
    return ok, findings
