#!/usr/bin/env python3
"""
merkle.py, inclusion-proof primitives for the Beacon Collector (0.5+).

Purpose: let a holder prove that ONE item is in a sealed package, to someone who
never sees the other items. Today a package is all-or-nothing: to prove one thing
you hand over everything, which is exactly the exposure that makes subjects wary.

Design notes, because the details here are the difference between a real proof and
a decoration:

  * Leaves are the EXISTING item_sha256 values, in package item order. Nothing new
    is hashed at collection time, and the leaf of an item is already what the
    package commits to.
  * Domain separation, RFC 6962 style: a leaf is H(0x00 || item_hash) and an
    internal node is H(0x01 || left || right). Without this, an internal node can
    be replayed as a leaf (second-preimage) and a proof can be forged.
  * Odd nodes are PROMOTED to the next level, not duplicated. Duplicating the last
    node is the Bitcoin construction and carries CVE-2012-2459, where two distinct
    trees share a root.
  * Escrow headroom: a leaf commits to the ITEM, and the item references its raw
    artifact by `artifact_ref` / `source.raw_sha256`, which is the hash of the
    PLAINTEXT artifact. Encrypting blobs at rest therefore changes no leaf and
    invalidates no proof. Per-item encryption can be added later without reissuing
    a single seal. Do not "optimise" this by hashing blob ciphertext into leaves.

No CLI here. No signing here. Hashes only.
"""
import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_digest(item_hash_hex: str) -> bytes:
    """H(0x00 || item_sha256). Takes the hex item hash already in the package."""
    return _h(LEAF_PREFIX + bytes.fromhex(item_hash_hex))


def node_digest(left: bytes, right: bytes) -> bytes:
    """H(0x01 || left || right)."""
    return _h(NODE_PREFIX + left + right)


def _levels(item_hashes: list) -> list:
    """All tree levels, bottom (leaves) to top (root). Empty list for no items."""
    if not item_hashes:
        return []
    level = [leaf_digest(h) for h in item_hashes]
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(node_digest(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])  # promote, never duplicate
        level = nxt
        levels.append(level)
    return levels


def merkle_root(item_hashes: list) -> str:
    """Hex root over the item hashes, in order. Empty package -> empty string."""
    levels = _levels(item_hashes)
    if not levels:
        return ""
    return levels[-1][0].hex()


def inclusion_proof(item_hashes: list, index: int) -> list:
    """Sibling path for item at `index`.

    Returns a list of {"sibling": hex, "side": "left"|"right"} ordered bottom-up.
    `side` is the side the SIBLING sits on, so a verifier knows the concat order.
    A promoted node has no sibling at that level and contributes no step.
    """
    if index < 0 or index >= len(item_hashes):
        raise IndexError("item index %d outside package of %d items" % (index, len(item_hashes)))
    levels = _levels(item_hashes)
    proof = []
    idx = index
    for level in levels[:-1]:
        if idx % 2 == 0:
            sib = idx + 1
            if sib < len(level):
                proof.append({"sibling": level[sib].hex(), "side": "right"})
            # else: promoted to the next level unpaired, so no step is recorded.
            # The index still halves: for an odd-length level L the promoted node
            # sits at L-1, and (L-1)//2 == L//2, its position one level up.
        else:
            proof.append({"sibling": level[idx - 1].hex(), "side": "left"})
        idx //= 2
    return proof


def verify_inclusion(item_hash_hex: str, proof: list, expected_root_hex: str) -> bool:
    """Recompute the root from one item hash and its sibling path.

    This is the whole point: the verifier needs the item hash, ~log2(n) sibling
    hashes, and the signed root. It never sees, and cannot derive, any other item.
    """
    if not expected_root_hex:
        return False
    cur = leaf_digest(item_hash_hex)
    for step in proof:
        sib = bytes.fromhex(step["sibling"])
        if step.get("side") == "left":
            cur = node_digest(sib, cur)
        elif step.get("side") == "right":
            cur = node_digest(cur, sib)
        else:
            return False
    return cur.hex() == expected_root_hex
