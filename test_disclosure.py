#!/usr/bin/env python3
"""End-to-end tests for seal v1 and selective disclosure.

Run: python test_disclosure.py

The claim under test is "a recipient learns that this one item is in the sealed
package, and learns nothing else, and cannot be fooled." A proof system that only
gets tested on the happy path is decoration, so most of what follows is forgeries
that must be refused.
"""
import copy
import io
import json
import os
import sys
import contextlib

import beaconlib as bl
import merkle

HOME = os.path.expanduser("~/.beacon")
fails = []


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def quiet(fn, *a, **k):
    """Run a verifier, swallow its printing, return (ok, output)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **k)
    return r, buf.getvalue()


def _test_key():
    """An ephemeral signing key for tests.

    Deliberately NOT the enrolled household key: that one is passphrase-protected at
    rest (correctly), and a test suite must never need it. The verification path
    exercised here is identical whichever key signed.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    import base64
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return priv, base64.b64encode(pub_raw).decode()


def _sign_with_test_key(pkg):
    import base64
    priv, pub_b64 = _test_key()
    header_hash = pkg["seal"]["header_sha256"]
    pkg["seal"]["signature"] = {
        "alg": "ed25519", "collector_id": "test-collector",
        "key_fingerprint": bl.sha256(pub_b64.encode())[:16],
        "public_key_ed25519_b64": pub_b64,
        "sig_b64": base64.b64encode(priv.sign(header_hash.encode())).decode(),
        "signs": "seal.header_sha256",
    }
    return pkg


def make_pkg(n=17, sign=True):
    items = []
    for i in range(n):
        items.append({
            "subcriterion": "technology-v1:%d.1a" % i,
            "mode": "scanner",
            "source": {"tool": "test", "raw_sha256": bl.sha256(("raw-%d" % i).encode())},
            "observation": {"fact_%d" % i: {"present": True}},
            "artifact_ref": "blob/sha256-" + bl.sha256(("raw-%d" % i).encode()),
            "collected_utc": "2026-08-28T00:00:00+00:00",
        })
    core = bl.build_package({"name": "Test Subject", "scope": "unit test",
                             "collected_utc": "2026-08-28T00:00:00+00:00"},
                            {"name": "test", "version": "0.5", "platform": "macos"}, items)
    pkg = bl.seal_and_sign(core, False, HOME)
    return _sign_with_test_key(pkg) if sign else pkg


print("seal v1 shape")
pkg = make_pkg()
seal = pkg["seal"]
check("seal_version is 1", seal.get("seal_version") == 1)
check("merkle_root present and non-empty", bool(seal.get("merkle_root")))
check("header_sha256 present", bool(seal.get("header_sha256")))
check("signature signs the header, not the package hash", seal["signature"].get("signs") == "seal.header_sha256")
check("merkle algorithm is declared", "rfc6962" in seal.get("merkle_alg", ""))

print("\nfull package verification")
ok, out = quiet(bl.verify_package, pkg)
check("a freshly sealed v1 package verifies", ok and "VALID" in out)

print("\ntamper detection on the full package")
t = copy.deepcopy(pkg)
t["items"][3]["observation"] = {"lie": True}
ok, _ = quiet(bl.verify_package, t)
check("editing an item is caught", not ok)

t = copy.deepcopy(pkg)
t["seal"]["merkle_root"] = merkle.merkle_root([bl.sha256(b"x")])
ok, out = quiet(bl.verify_package, t)
check("swapping the merkle_root is caught", not ok and "merkle_root" in out)

t = copy.deepcopy(pkg)
t["items"] = t["items"][:8]
ok, _ = quiet(bl.verify_package, t)
check("dropping items from a sealed package is caught", not ok)

print("\ndisclosure of one item")
d = bl.build_disclosure(pkg, 7)
ok, out = quiet(bl.verify_disclosure, d)
check("a single-item disclosure verifies", ok and "VALID" in out)
check("the bundle carries exactly one item", "item" in d and isinstance(d["item"], dict))
check("no other items travel in the bundle", "items" not in d)
check("proof is logarithmic, not the whole package", len(d["proof"]) <= 5)
check("artifact defaults to withheld", d["artifact_disclosure"] == "withheld")

print("\nhash-only disclosure, the item itself withheld")
d2 = bl.build_disclosure(pkg, 2, include_item=False)
ok, _ = quiet(bl.verify_disclosure, d2)
check("existence can be proven without disclosing the item at all", ok)
check("hash-only bundle contains no item body", "item" not in d2)

print("\nforgeries that must be refused")
f = copy.deepcopy(d)
f["item"]["observation"] = {"tampered": True}
ok, out = quiet(bl.verify_disclosure, f)
check("altering the disclosed item is refused", not ok)

f = copy.deepcopy(d)
f["item"] = copy.deepcopy(pkg["items"][8])
f["item_sha256"] = pkg["items"][8]["item_sha256"]
ok, out = quiet(bl.verify_disclosure, f)
check("substituting a different real item under the same proof is refused", not ok)

f = copy.deepcopy(d)
f["header"]["subject"]["name"] = "Someone Else"
ok, out = quiet(bl.verify_disclosure, f)
check("editing the header breaks the signature", not ok and "SIGNATURE INVALID" in out)

f = copy.deepcopy(d)
f["header"]["merkle_root"] = merkle.merkle_root([bl.sha256(b"y")])
ok, _ = quiet(bl.verify_disclosure, f)
check("editing the root in the header is refused", not ok)

f = copy.deepcopy(d)
f["proof"] = []
ok, _ = quiet(bl.verify_disclosure, f)
check("stripping the proof is refused", not ok)

foreign = make_pkg(n=9)
f = copy.deepcopy(d)
f["item"] = foreign["items"][0]
f["item_sha256"] = foreign["items"][0]["item_sha256"]
ok, _ = quiet(bl.verify_disclosure, f)
check("an item from another package is refused", not ok)

print("\nv0 packages cannot silently produce proofs")
v0 = copy.deepcopy(pkg)
del v0["seal"]["seal_version"]
del v0["seal"]["merkle_root"]
try:
    bl.build_disclosure(v0, 1)
    check("disclosing from a v0 package raises rather than faking a proof", False)
except ValueError:
    check("disclosing from a v0 package raises rather than faking a proof", True)

print("\nwithheld versus tampered blobs")
tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".test_blobs")
os.makedirs(tmp, exist_ok=True)
for fn in os.listdir(tmp):
    os.remove(os.path.join(tmp, fn))
for i, it in enumerate(pkg["items"]):
    rh = it["source"]["raw_sha256"]
    if i == 5:
        continue  # this one is deliberately absent
    with open(os.path.join(tmp, "sha256-" + rh + ".json"), "wb") as fh:
        fh.write(("raw-%d" % i).encode())

absent = pkg["items"][5]["source"]["raw_sha256"]

ok, out = quiet(bl.verify_package, pkg, tmp)
check("an undeclared missing blob is still a rejection", not ok and "MISSING blob" in out)

ok, out = quiet(bl.verify_package, pkg, tmp, None, [absent])
check("a DECLARED withheld blob verifies as partial disclosure", ok and "partial disclosure" in out)
check("partial disclosure says the seals are intact", "seals intact" in out)

with open(os.path.join(tmp, "sha256-" + pkg["items"][2]["source"]["raw_sha256"] + ".json"), "wb") as fh:
    fh.write(b"swapped content")
ok, out = quiet(bl.verify_package, pkg, tmp, None, [absent])
check("a present-but-corrupted blob is still TAMPERED", not ok and "TAMPERED blob" in out)

for fn in os.listdir(tmp):
    os.remove(os.path.join(tmp, fn))
os.rmdir(tmp)

print("\nescrow headroom")
check("leaves commit to items, not to blob bytes",
      merkle.merkle_root([i["item_sha256"] for i in pkg["items"]]) == pkg["seal"]["merkle_root"])
check("artifact_ref names the plaintext hash, so encrypting blobs later changes no leaf",
      pkg["items"][0]["artifact_ref"].endswith(pkg["items"][0]["source"]["raw_sha256"]))
check("disclosure state is a field, so 'encrypted' can join 'withheld'/'included' later",
      d["artifact_disclosure"] in ("withheld", "included"))

print("\n%d checks failed" % len(fails))
sys.exit(1 if fails else 0)
