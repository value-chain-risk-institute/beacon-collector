#!/usr/bin/env python3
"""
send.py, Beacon Collector 0.3 send-path: hybrid post-quantum confidential send.

Proves CONFIDENTIALITY + a harvest-now-decrypt-later hedge (the remaining half
of the 0.3 milestone; the signing half shipped 2026-07-29). A sealed, signed
evidence package is encrypted to VCRI escrow's long-term key so only escrow can
read it in transit, and it stays confidential even against a future quantum
adversary who recorded the traffic today.

Hybrid KEM (belt and suspenders, the industry-standard construction):
  - X25519 ECDH  (classical; safe unless X25519 breaks)
  - ML-KEM-768   (FIPS 203, post-quantum; safe unless ML-KEM breaks)
  - shared secret = HKDF-SHA256(ss_x25519 || ss_mlkem)   both must fall to lose it
  - payload = AES-256-GCM(canonical(package))

Vetted libraries only (invariant 7): X25519/HKDF/AES-GCM from `cryptography`;
ML-KEM from liboqs (open-quantum-safe) via the `oqs` binding. We do NOT implement
any primitive ourselves; we only compose them in the standard hybrid pattern.

liboqs note: `oqs` needs Python >= 3.10. Run this on a 3.10+ host (Framework
py3.13). The classical half is testable anywhere `cryptography` is present; the
module degrades to an explicit error if `oqs` is missing rather than silently
dropping the PQC leg (never weaken crypto silently).

  send.py keygen  --out-dir escrow-keys                 # VCRI/escrow side: make recipient keypair
  send.py send    --package PKG.json --recipient escrow-keys/recipient.pub.json --out envelope.json
  send.py receive --envelope envelope.json --keys escrow-keys --out received-package.json
"""
import argparse
import base64
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MLKEM_ALG = "ML-KEM-768"


def b64e(b):
    return base64.b64encode(b).decode()


def b64d(s):
    return base64.b64decode(s)


def _oqs():
    try:
        import oqs
        return oqs
    except ImportError:
        sys.exit("liboqs binding 'oqs' not available (needs Python >=3.10 + liboqs). "
                 "Run on Framework py3.13; refusing to send without the PQC leg.")


def hkdf(ss_classical: bytes, ss_pq: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"vcri.beacon.hybrid-kem/v0").derive(ss_classical + ss_pq)


# ---------------- keygen (recipient / escrow side) ----------------

def keygen(args):
    oqs = _oqs()
    os.makedirs(args.out_dir, exist_ok=True)

    x_priv = X25519PrivateKey.generate()
    x_pub = x_priv.public_key()
    x_priv_raw = x_priv.private_bytes(serialization.Encoding.Raw,
                                      serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption())
    x_pub_raw = x_pub.public_bytes(serialization.Encoding.Raw,
                                   serialization.PublicFormat.Raw)

    with oqs.KeyEncapsulation(MLKEM_ALG) as kem:
        mlkem_pub = kem.generate_keypair()
        mlkem_secret = kem.export_secret_key()

    key_id = "escrow-" + base64.b16encode(x_pub_raw[:6]).decode().lower()
    pub_bundle = {"schema": "vcri.beacon.recipient-key/v0", "key_id": key_id,
                  "x25519_pub_b64": b64e(x_pub_raw),
                  "mlkem_alg": MLKEM_ALG, "mlkem_pub_b64": b64e(mlkem_pub)}
    priv_bundle = {"key_id": key_id,
                   "x25519_priv_b64": b64e(x_priv_raw),
                   "mlkem_alg": MLKEM_ALG, "mlkem_priv_b64": b64e(mlkem_secret),
                   "warning": "SECRET. Escrow-side only. Never ships with the collector."}

    with open(os.path.join(args.out_dir, "recipient.pub.json"), "w") as f:
        json.dump(pub_bundle, f, indent=2)
    priv_path = os.path.join(args.out_dir, "recipient.secret.json")
    with open(priv_path, "w") as f:
        json.dump(priv_bundle, f, indent=2)
    os.chmod(priv_path, 0o600)
    print("recipient keypair -> %s (key_id %s)" % (args.out_dir, key_id))
    print("  ship recipient.pub.json to collectors; keep recipient.secret.json on the escrow side only")


# ---------------- send (collector side) ----------------

def send(args):
    oqs = _oqs()
    pub = json.load(open(args.recipient))
    with open(args.package, "rb") as f:
        plaintext = f.read()

    # classical leg: ephemeral X25519 ECDH
    eph = X25519PrivateKey.generate()
    eph_pub_raw = eph.public_key().public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw)
    peer_x = X25519PublicKey.from_public_bytes(b64d(pub["x25519_pub_b64"]))
    ss_classical = eph.exchange(peer_x)

    # pq leg: ML-KEM encapsulate to recipient pubkey
    with oqs.KeyEncapsulation(pub["mlkem_alg"]) as kem:
        mlkem_ct, ss_pq = kem.encap_secret(b64d(pub["mlkem_pub_b64"]))

    key = hkdf(ss_classical, ss_pq)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, b"vcri.beacon.envelope/v0")

    envelope = {
        "schema": "vcri.beacon.envelope/v0",
        "recipient_key_id": pub["key_id"],
        "kem": {"classical": "x25519", "pq": pub["mlkem_alg"],
                "combine": "hkdf-sha256(ss_x25519||ss_mlkem)"},
        "x25519_eph_pub_b64": b64e(eph_pub_raw),
        "mlkem_ct_b64": b64e(mlkem_ct),
        "aead": "aes-256-gcm", "nonce_b64": b64e(nonce),
        "ciphertext_b64": b64e(ct),
        "note": "confidentiality only; the package inside carries its own seal+signature (integrity/identity)",
    }
    with open(args.out, "w") as f:
        json.dump(envelope, f, indent=2)
    print("sealed package encrypted -> %s" % args.out)
    print("  hybrid X25519 + %s; recipient %s; %d bytes plaintext" % (
        pub["mlkem_alg"], pub["key_id"], len(plaintext)))
    print("  transport is org-controlled; this only produces the confidential envelope")


# ---------------- receive (escrow side) ----------------

def receive(args):
    oqs = _oqs()
    env = json.load(open(args.envelope))
    sec = json.load(open(os.path.join(args.keys, "recipient.secret.json")))
    if env["recipient_key_id"] != sec["key_id"]:
        sys.exit("envelope is for key_id %s, this escrow key is %s" % (
            env["recipient_key_id"], sec["key_id"]))

    x_priv = X25519PrivateKey.from_private_bytes(b64d(sec["x25519_priv_b64"]))
    eph_pub = X25519PublicKey.from_public_bytes(b64d(env["x25519_eph_pub_b64"]))
    ss_classical = x_priv.exchange(eph_pub)

    with oqs.KeyEncapsulation(sec["mlkem_alg"], b64d(sec["mlkem_priv_b64"])) as kem:
        ss_pq = kem.decap_secret(b64d(env["mlkem_ct_b64"]))

    key = hkdf(ss_classical, ss_pq)
    try:
        plaintext = AESGCM(key).decrypt(b64d(env["nonce_b64"]),
                                        b64d(env["ciphertext_b64"]),
                                        b"vcri.beacon.envelope/v0")
    except Exception:
        sys.exit("decryption failed: wrong key or tampered envelope")
    with open(args.out, "wb") as f:
        f.write(plaintext)
    print("decrypted package -> %s (verify its seal/signature next with collector.py verify)" % args.out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--out-dir", default="escrow-keys")
    s = sub.add_parser("send")
    s.add_argument("--package", required=True); s.add_argument("--recipient", required=True)
    s.add_argument("--out", default="envelope.json")
    r = sub.add_parser("receive")
    r.add_argument("--envelope", required=True); r.add_argument("--keys", default="escrow-keys")
    r.add_argument("--out", default="received-package.json")
    a = ap.parse_args()
    {"keygen": keygen, "send": send, "receive": receive}[a.cmd](a)
