#!/usr/bin/env python3
"""
beaconlib.py, shared primitives for the Beacon Collector (0.4+).

Extracted so every collection mode (scanner via collector.py, document via
docs.py, later export) produces byte-identical seals and signatures. One
implementation of the trust math, imported everywhere. No CLI here.

Invariants served (see SPEC.md): SHA-256 seals, per-item + package hashes,
Ed25519 identity signatures over the package_hash, subject claims labeled,
never-roll-own-crypto (all crypto from the vetted `cryptography` lib).
"""
import hashlib
import json
from datetime import datetime, timezone

SCHEMA = "vcri.beacon.evidence-package/v0"

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_item(item: dict) -> str:
    """item_sha256 over everything except the hash field itself."""
    core = {k: v for k, v in item.items() if k != "item_sha256"}
    return sha256(canonical(core))


def completeness(observation: dict, expected: list) -> dict:
    got = [k for k in expected if observation.get(k, {}).get("present")]
    return {"expected": expected, "obtained": got,
            "fraction": round(len(got) / len(expected), 3) if expected else None,
            "note": "coverage of THIS item's evidence, not a posture grade"}


def build_package(subject: dict, collector: dict, items: list) -> dict:
    for it in items:
        it["item_sha256"] = hash_item(it)
    return {"schema": SCHEMA, "subject": subject, "collector": collector, "items": items}


def seal_and_sign(core: dict, sign: bool, home: str) -> dict:
    """Return a full package = core + seal. If sign, attach an Ed25519 signature
    over package_hash using the enrolled identity key (via enroll.py)."""
    package_hash = sha256(canonical(core))
    seal = {"alg": "sha256", "package_hash": package_hash,
            "anchor": "STUB-opentimestamps",
            "note": "per-item item_sha256 + package_hash; edit anything above and verify fails"}
    if sign:
        if not HAVE_CRYPTO:
            raise RuntimeError("--sign needs the cryptography library")
        import enroll
        priv = enroll.load_private_key(home)
        rec = enroll.load_enrollment(home)
        import base64
        seal["signature"] = {
            "alg": "ed25519", "collector_id": rec["collector_id"],
            "key_fingerprint": rec["key_fingerprint"],
            "public_key_ed25519_b64": rec["public_key_ed25519_b64"],
            "sig_b64": base64.b64encode(priv.sign(package_hash.encode())).decode(),
            "signs": "seal.package_hash",
            "note": "identity proof: only the enrolled collector's key produces this over the package_hash"}
    else:
        seal["signature"] = {"alg": "none", "note": "unsigned (0.2 mode); enroll + --sign for identity"}
    return {**core, "seal": seal}


def verify_package(pkg: dict, blob_dir: str = None, registry: str = None) -> bool:
    """Full verification: per-item hashes, package hash, optional signature +
    registry anti-forge, optional raw-blob integrity. Prints findings, returns ok."""
    import base64
    import os
    ok = True

    for i, it in enumerate(pkg.get("items", [])):
        if hash_item(it) != it.get("item_sha256"):
            print("TAMPERED item[%d] (%s): item_sha256 mismatch" % (i, it.get("subcriterion")))
            ok = False

    claimed_pkg = pkg.get("seal", {}).get("package_hash")
    core = {k: v for k, v in pkg.items() if k != "seal"}
    if sha256(canonical(core)) != claimed_pkg:
        print("TAMPERED package: package_hash mismatch")
        ok = False

    sig = pkg.get("seal", {}).get("signature", {})
    if sig.get("alg") == "ed25519":
        if not HAVE_CRYPTO:
            print("note: signed package but cryptography unavailable; signature NOT checked")
        else:
            expected_pub = sig["public_key_ed25519_b64"]
            if registry:
                reg_path = os.path.join(os.path.expanduser(registry), sig["collector_id"] + ".json")
                if os.path.exists(reg_path):
                    reg_pub = json.load(open(reg_path))["public_key_ed25519_b64"]
                    if reg_pub != expected_pub:
                        print("FORGED: package key does not match registry for %s" % sig["collector_id"])
                        ok = False
                    expected_pub = reg_pub
                else:
                    print("note: collector %s not in registry; verifying against in-package key only" % sig["collector_id"])
            try:
                pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(expected_pub))
                pub.verify(base64.b64decode(sig["sig_b64"]), claimed_pkg.encode())
                print("signature VALID: package_hash signed by %s (fp %s)" % (
                    sig["collector_id"], sig["key_fingerprint"]))
            except (InvalidSignature, Exception) as e:
                print("SIGNATURE INVALID: %s" % type(e).__name__)
                ok = False
    elif sig.get("alg") == "none":
        print("note: package is unsigned (0.2 mode); hash seal verified, identity NOT proven")

    if blob_dir:
        seen = set()
        for it in pkg.get("items", []):
            rh = it.get("source", {}).get("raw_sha256")
            if not rh or rh in seen:
                continue
            seen.add(rh)
            bpath = os.path.join(blob_dir, "sha256-" + rh + ".json")
            if os.path.exists(bpath):
                with open(bpath, "rb") as f:
                    if sha256(f.read()) != rh:
                        print("TAMPERED blob: content does not match raw_sha256 (%s)" % rh[:12])
                        ok = False

    print("VALID: all seals intact; safe to score." if ok
          else "REJECT this package: it was edited after collection.")
    return ok
