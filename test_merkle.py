#!/usr/bin/env python3
"""Tests for merkle.py. Run: python test_merkle.py

Written before the integration, deliberately: the failure mode of a proof system is
that it says VALID for things it should refuse, and that is invisible unless the
negative cases are asserted explicitly.
"""
import hashlib
import sys

import merkle as m

fails = []


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def hx(n):
    """Deterministic stand-in item hashes."""
    return hashlib.sha256(("item-%d" % n).encode()).hexdigest()


print("empty and single")
check("empty package has empty root", m.merkle_root([]) == "")
one = [hx(0)]
check("single-item root is the leaf digest", m.merkle_root(one) == m.leaf_digest(hx(0)).hex())
check("single-item proof is empty", m.inclusion_proof(one, 0) == [])
check("single-item proof verifies", m.verify_inclusion(hx(0), [], m.merkle_root(one)))

print("\nround trip, every index, sizes 1 through 33")
allok = True
for n in range(1, 34):
    items = [hx(i) for i in range(n)]
    root = m.merkle_root(items)
    for i in range(n):
        p = m.inclusion_proof(items, i)
        if not m.verify_inclusion(items[i], p, root):
            allok = False
            print("    size %d index %d did not verify" % (n, i))
check("every item in every size verifies against its root", allok)

print("\nproof size is logarithmic")
items = [hx(i) for i in range(17)]
root17 = m.merkle_root(items)
check("17 items yields a proof of at most 5 steps", len(m.inclusion_proof(items, 0)) <= 5)

print("\nnegative cases, the ones that matter")
check("a foreign item hash is refused",
      not m.verify_inclusion(hx(999), m.inclusion_proof(items, 3), root17))
check("an item does not verify under another item's proof",
      not m.verify_inclusion(items[4], m.inclusion_proof(items, 3), root17))
tampered = m.inclusion_proof(items, 3)
tampered[0]["sibling"] = hx(1234)
check("a corrupted sibling is refused", not m.verify_inclusion(items[3], tampered, root17))
flipped = m.inclusion_proof(items, 3)
for s in flipped:
    s["side"] = "left" if s["side"] == "right" else "right"
check("flipping concat order is refused", not m.verify_inclusion(items[3], flipped, root17))
check("an empty root refuses everything", not m.verify_inclusion(items[3], m.inclusion_proof(items, 3), ""))
check("an unknown side value is refused",
      not m.verify_inclusion(items[3], [{"sibling": hx(1), "side": "sideways"}], root17))

print("\ndomain separation, the second-preimage guard")
a, b = hx(1), hx(2)
internal = m.node_digest(m.leaf_digest(a), m.leaf_digest(b))
check("an internal node cannot be replayed as a leaf",
      m.leaf_digest(internal.hex()) != internal)

print("\nodd nodes are promoted, not duplicated")
three = [hx(0), hx(1), hx(2)]
four_dup = [hx(0), hx(1), hx(2), hx(2)]
check("3 items and 3+duplicate do not share a root (CVE-2012-2459 shape)",
      m.merkle_root(three) != m.merkle_root(four_dup))

print("\norder is committed")
check("reordering items changes the root",
      m.merkle_root([hx(0), hx(1)]) != m.merkle_root([hx(1), hx(0)]))

print("\nbounds")
try:
    m.inclusion_proof(items, 17)
    check("out-of-range index raises", False)
except IndexError:
    check("out-of-range index raises", True)

print("\n%d checks failed" % len(fails))
sys.exit(1 if fails else 0)
