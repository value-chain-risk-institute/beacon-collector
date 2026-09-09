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
import os
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


SEAL_VERSION = 1


def seal_header(core: dict, package_hash: str, merkle_root_hex: str) -> dict:
    """The small, fully disclosable object a signature commits to (seal v1).

    Why a header instead of signing package_hash directly: package_hash can only be
    recomputed by someone holding every item, so a signature over it is unverifiable
    to a partial recipient. The header is a handful of fields, safe to hand over
    whole, and it carries the merkle_root that an inclusion proof resolves against.
    That is what makes selective disclosure possible without a second key.
    """
    return {"schema": core.get("schema"), "subject": core.get("subject"),
            "collector": core.get("collector"), "item_count": len(core.get("items", [])),
            "package_hash": package_hash, "merkle_root": merkle_root_hex}


def seal_and_sign(core: dict, sign: bool, home: str) -> dict:
    """Return a full package = core + seal.

    Seal v1 adds a merkle_root over the item hashes and signs a header digest, so a
    single item can be proven to a party who never receives the others. Seal v0
    packages (no seal_version, signature over package_hash) remain valid forever and
    are still accepted by verify_package. Fixed forward, history not rewritten.
    """
    import merkle
    package_hash = sha256(canonical(core))
    item_hashes = [it["item_sha256"] for it in core.get("items", [])]
    root = merkle.merkle_root(item_hashes)
    header = seal_header(core, package_hash, root)
    header_hash = sha256(canonical(header))

    seal = {"alg": "sha256", "seal_version": SEAL_VERSION,
            "package_hash": package_hash,
            "merkle_root": root,
            "merkle_alg": "rfc6962-sha256/promote-odd",
            "header_sha256": header_hash,
            "anchor": "STUB-opentimestamps",
            "note": "per-item item_sha256, merkle_root over them, package_hash over the whole; "
                    "edit anything above and verify fails"}
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
            "sig_b64": base64.b64encode(priv.sign(header_hash.encode())).decode(),
            "signs": "seal.header_sha256",
            "note": "identity proof over the disclosable header; the header carries the merkle_root, "
                    "so one item can be proven without releasing the rest"}
    else:
        seal["signature"] = {"alg": "none", "note": "unsigned (0.2 mode); enroll + --sign for identity"}
    return {**core, "seal": seal}


def verify_package(pkg: dict, blob_dir: str = None, registry: str = None,
                   withheld: list = None) -> bool:
    """Full verification: per-item hashes, merkle root and header (seal v1), package
    hash, optional signature + registry anti-forge, optional raw-blob integrity.

    `withheld` is a list of raw_sha256 values the holder has DECLARED it is not
    releasing. Declared-absent is a valid partial disclosure; undeclared-absent is
    still a rejection, so that deleting evidence cannot be passed off as discretion.
    Prints findings, returns ok.
    """
    import base64
    import os
    ok = True
    unverifiable = False

    for i, it in enumerate(pkg.get("items", [])):
        if hash_item(it) != it.get("item_sha256"):
            print("TAMPERED item[%d] (%s): item_sha256 mismatch" % (i, it.get("subcriterion")))
            ok = False

    seal = pkg.get("seal", {})
    claimed_pkg = seal.get("package_hash")
    core = {k: v for k, v in pkg.items() if k != "seal"}
    if sha256(canonical(core)) != claimed_pkg:
        print("TAMPERED package: package_hash mismatch")
        ok = False

    # Seal version dispatch. v0 signed package_hash directly; v1 signs a small
    # disclosable header that carries the merkle_root. Both stay valid: the 80-odd
    # packages sealed before this existed must never stop verifying.
    seal_version = seal.get("seal_version", 0)
    signed_target = claimed_pkg

    if seal_version >= 1:
        import merkle
        item_hashes = [it.get("item_sha256") for it in pkg.get("items", [])]
        recomputed_root = merkle.merkle_root(item_hashes)
        if recomputed_root != seal.get("merkle_root"):
            print("TAMPERED package: merkle_root does not match the items present")
            ok = False
        header = seal_header(core, claimed_pkg, seal.get("merkle_root"))
        recomputed_header = sha256(canonical(header))
        if recomputed_header != seal.get("header_sha256"):
            print("TAMPERED package: header_sha256 mismatch")
            ok = False
        signed_target = seal.get("header_sha256")

    sig = seal.get("signature", {})
    if sig.get("alg") == "ed25519":
        if not HAVE_CRYPTO:
            if os.environ.get("BEACON_ALLOW_UNVERIFIED") == "1":
                print("WARNING: signed package, cryptography unavailable, signature NOT checked "
                      "(BEACON_ALLOW_UNVERIFIED=1). Hashes were checked; authenticity was not.")
            else:
                print("CANNOT VERIFY: package carries an ed25519 signature but the cryptography "
                      "library is unavailable in this interpreter, so authenticity was NOT checked. "
                      "Install the dependency (pip install 'cryptography>=42') or re-run with the "
                      "collector venv. Set BEACON_ALLOW_UNVERIFIED=1 to accept hash-only checking.")
                unverifiable = True
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
                pub.verify(base64.b64decode(sig["sig_b64"]), signed_target.encode())
                print("signature VALID: %s signed by %s (fp %s)" % (
                    "header_sha256" if seal_version >= 1 else "package_hash",
                    sig["collector_id"], sig["key_fingerprint"]))
            except (InvalidSignature, Exception) as e:
                print("SIGNATURE INVALID: %s" % type(e).__name__)
                ok = False
    elif sig.get("alg") == "none":
        print("note: package is unsigned (0.2 mode); hash seal verified, identity NOT proven")

    withheld_seen = []
    if blob_dir:
        declared = set(withheld or [])
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
            elif rh in declared:
                # DECLARED withheld. The holder chose not to release this artifact and
                # said so. The item itself, its hash, and the seal over it all still
                # verify, so integrity is intact and only reach is reduced.
                withheld_seen.append(rh)
            else:
                # Undeclared absence. The original judgment stands and is deliberate:
                # a blob that is simply gone is a broken chain of custody, and it must
                # not be possible to launder deletion as discretion by staying silent.
                print("MISSING blob: raw evidence sha256-%s is referenced but not present in %s" % (rh[:12], blob_dir))
                print("             (if this was withheld on purpose, declare it: withheld artifacts are accepted)")
                ok = False

    undeclared = set(withheld or []) - set(withheld_seen)
    if undeclared:
        for rh in sorted(undeclared):
            print("note: sha256-%s was declared withheld but is present or unreferenced" % rh[:12])

    if not ok:
        print("REJECT this package: it was edited after collection.")
    elif unverifiable:
        print("INCONCLUSIVE: every hash and the merkle root check out, but the signature could not be "
              "checked in this environment. The package is NOT known to be tampered with; it is "
              "unproven. Do not score it until it verifies with cryptography available.")
    elif withheld_seen:
        print("VALID (partial disclosure): all seals intact; %d raw artifact(s) withheld by the holder." % len(withheld_seen))
        print("       every item hash, the merkle root and the signature verify; the withheld bytes are simply absent.")
    else:
        print("VALID: all seals intact; safe to score.")
    return ok and not unverifiable


def build_disclosure(pkg: dict, index: int, include_item: bool = True,
                     blob_dir: str = None, include_blob: bool = False) -> dict:
    """Build a minimal bundle proving ONE item is in a sealed package.

    The recipient gets the signed header, the signature, an inclusion proof, and
    either the item itself or only its hash. They never receive, and cannot derive,
    any other item. Seal v1 only: v0 packages have no merkle_root to prove against.
    """
    import merkle
    seal = pkg.get("seal", {})
    if seal.get("seal_version", 0) < 1:
        raise ValueError("package is seal v0: no merkle_root, cannot build an inclusion proof. Re-seal to disclose.")
    items = pkg.get("items", [])
    if index < 0 or index >= len(items):
        raise IndexError("item index %d outside package of %d items" % (index, len(items)))

    item = items[index]
    item_hash = item["item_sha256"]
    core = {k: v for k, v in pkg.items() if k != "seal"}
    header = seal_header(core, seal.get("package_hash"), seal.get("merkle_root"))

    bundle = {
        "schema": "vcri.beacon.disclosure/v0",
        "header": header,
        "signature": seal.get("signature", {}),
        "item_sha256": item_hash,
        "item_index": index,
        "proof": merkle.inclusion_proof([i["item_sha256"] for i in items], index),
        "artifact_disclosure": "withheld",
        "note": "proves this item is in the sealed package; the other items are absent by design",
    }
    if include_item:
        bundle["item"] = item
    if include_blob and blob_dir:
        import os
        rh = item.get("source", {}).get("raw_sha256")
        bpath = os.path.join(blob_dir, "sha256-" + str(rh) + ".json")
        if rh and os.path.exists(bpath):
            bundle["artifact_disclosure"] = "included"
            bundle["artifact_raw_sha256"] = rh
    return bundle


def verify_disclosure(bundle: dict, registry: str = None) -> bool:
    """Verify a one-item disclosure without ever seeing the rest of the package."""
    import base64
    import os
    import merkle
    ok = True
    unverifiable = False

    header = bundle.get("header", {})
    header_hash = sha256(canonical(header))
    root = header.get("merkle_root")

    item_hash = bundle.get("item_sha256")
    if "item" in bundle:
        recomputed = hash_item(bundle["item"])
        if recomputed != item_hash:
            print("TAMPERED item: item_sha256 does not match the disclosed item")
            ok = False
        item_hash = recomputed

    if not merkle.verify_inclusion(item_hash, bundle.get("proof", []), root):
        print("NOT IN PACKAGE: inclusion proof does not resolve to the signed merkle_root")
        ok = False

    sig = bundle.get("signature", {})
    if sig.get("alg") == "ed25519":
        if not HAVE_CRYPTO:
            if os.environ.get("BEACON_ALLOW_UNVERIFIED") == "1":
                print("WARNING: signed disclosure, cryptography unavailable, signature NOT checked "
                      "(BEACON_ALLOW_UNVERIFIED=1). Hashes were checked; authenticity was not.")
            else:
                print("CANNOT VERIFY: disclosure carries an ed25519 signature but the cryptography "
                      "library is unavailable in this interpreter, so authenticity was NOT checked. "
                      "Set BEACON_ALLOW_UNVERIFIED=1 to accept hash-only checking.")
                unverifiable = True
        else:
            expected_pub = sig["public_key_ed25519_b64"]
            if registry:
                reg_path = os.path.join(os.path.expanduser(registry), sig["collector_id"] + ".json")
                if os.path.exists(reg_path):
                    reg_pub = json.load(open(reg_path))["public_key_ed25519_b64"]
                    if reg_pub != expected_pub:
                        print("FORGED: disclosure key does not match registry for %s" % sig["collector_id"])
                        ok = False
                    expected_pub = reg_pub
            try:
                pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(expected_pub))
                pub.verify(base64.b64decode(sig["sig_b64"]), header_hash.encode())
                print("signature VALID: header signed by %s (fp %s)" % (
                    sig["collector_id"], sig["key_fingerprint"]))
            except (InvalidSignature, Exception) as e:
                print("SIGNATURE INVALID: %s" % type(e).__name__)
                ok = False
    elif sig.get("alg") == "none":
        print("note: disclosure is unsigned; inclusion proven, identity NOT proven")

    if ok:
        subj = header.get("subject", {}) or {}
        print("VALID: item %s of %s is in the package sealed for %s at %s." % (
            bundle.get("item_index"), header.get("item_count"),
            subj.get("name", "?"), subj.get("collected_utc", "?")))
        print("       raw artifact: %s. The other %s items were never sent and cannot be derived." % (
            bundle.get("artifact_disclosure", "withheld"),
            (header.get("item_count") or 1) - 1))
    else:
        print("REJECT this disclosure.")
    return ok and not unverifiable
