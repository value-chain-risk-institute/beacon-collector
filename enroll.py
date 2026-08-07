#!/usr/bin/env python3
"""
enroll.py, Beacon Collector 0.3: collector identity + enrollment.

Proves IDENTITY (the 0.3 milestone). A collector enrolls ONCE, producing:
  - an Ed25519 identity keypair (the collector's long-term signing key)
  - a private key ENCRYPTED AT REST (scrypt-derived key + Fernet/AES128-CBC+HMAC)
  - an enrollment record binding collector_id -> public key, carrying the
    out-of-band token the operator pasted from the VCRI portal

Design decisions recorded here (Cairn, 2026-07-29, self-set per "cairn: decide";
the 0.3 open item "signing-key custody" is answered with a defensible default,
revisitable, not left blocking):

  KEY CUSTODY v0.3 = encrypted key FILE at ~/.beacon/identity.key, passphrase via
  BEACON_PASSPHRASE env or interactive prompt. Rationale: portable across the
  Mac/Linux collector hosts we actually run, no platform-specific keystore
  dependency, and the private key never touches disk in cleartext. TPM/Secure
  Enclave/OS-keychain custody is a hardening upgrade for a later version, not a
  0.3 blocker. Encryption is a vetted library (cryptography), never hand-rolled.

  ENROLLMENT TOKEN v0.3 = out-of-band string (operator pastes the portal-shown
  token). Here the "VCRI registry" is a local JSON stub; the real registry is the
  small VCRI-side service in the 0.3 server work. The OOB property (seed never
  crosses a harvestable channel) is preserved: the token is an input, not fetched.

Never rolls its own crypto. Ed25519 + scrypt + Fernet are all from `cryptography`.

  enroll.py init --collector-id NAME --token OOB-TOKEN [--home ~/.beacon]
  enroll.py show [--home ~/.beacon]
"""
import argparse
import base64
import getpass
import json
import os
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet

DEFAULT_HOME = os.path.expanduser("~/.beacon")


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def _fernet_from_passphrase(passphrase: bytes, salt: bytes) -> Fernet:
    # scrypt is the vetted KDF; parameters are the cryptography-docs defaults.
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    key = base64.urlsafe_b64encode(kdf.derive(passphrase))
    return Fernet(key)


def get_passphrase(confirm: bool) -> bytes:
    env = os.environ.get("BEACON_PASSPHRASE")
    if env:
        return env.encode()
    p = getpass.getpass("Beacon key passphrase: ")
    if confirm and getpass.getpass("Confirm passphrase: ") != p:
        sys.exit("passphrases did not match")
    if not p:
        sys.exit("empty passphrase refused")
    return p.encode()


def init(args):
    home = os.path.expanduser(args.home)
    key_path = os.path.join(home, "identity.key")
    rec_path = os.path.join(home, "enrollment.json")
    if os.path.exists(key_path) and not args.force:
        sys.exit("already enrolled at %s (use --force to re-enroll)" % home)
    os.makedirs(home, exist_ok=True)

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)

    passphrase = get_passphrase(confirm=True)
    salt = os.urandom(16)
    box = _fernet_from_passphrase(passphrase, salt)
    blob = {
        "v": 1,
        "salt": base64.b64encode(salt).decode(),
        "priv_enc": base64.b64encode(box.encrypt(priv_raw)).decode(),
    }
    with open(key_path, "w") as f:
        json.dump(blob, f)
    os.chmod(key_path, 0o600)

    pub_b64 = base64.b64encode(pub_raw).decode()
    collector_id = args.collector_id
    fingerprint = base64.b16encode(pub_raw[:8]).decode().lower()
    record = {
        "schema": "vcri.beacon.enrollment/v0",
        "collector_id": collector_id,
        "public_key_ed25519_b64": pub_b64,
        "key_fingerprint": fingerprint,
        "enrollment_token": args.token,          # OOB, operator-pasted
        "token_note": "out-of-band from VCRI portal; registry-side match is the anti-forge check",
        "enrolled_utc": utcnow(),
        "registry_endpoint": "STUB-local; real endpoint = VCRI enrollment service (0.3 server work)",
    }
    with open(rec_path, "w") as f:
        json.dump(record, f, indent=2)

    # Local registry stub: what the VCRI side would store to later verify packages.
    reg_dir = os.path.join(home, "registry-stub")
    os.makedirs(reg_dir, exist_ok=True)
    with open(os.path.join(reg_dir, collector_id + ".json"), "w") as f:
        json.dump({"collector_id": collector_id, "public_key_ed25519_b64": pub_b64,
                   "key_fingerprint": fingerprint, "registered_utc": utcnow()}, f, indent=2)

    print("enrolled collector '%s'" % collector_id)
    print("  fingerprint: %s" % fingerprint)
    print("  identity key (encrypted): %s" % key_path)
    print("  enrollment record: %s" % rec_path)
    print("  private key is encrypted at rest; packages will be SIGNED by this key")


def load_private_key(home: str) -> Ed25519PrivateKey:
    key_path = os.path.join(os.path.expanduser(home), "identity.key")
    if not os.path.exists(key_path):
        sys.exit("not enrolled (%s missing); run enroll.py init first" % key_path)
    blob = json.load(open(key_path))
    salt = base64.b64decode(blob["salt"])
    box = _fernet_from_passphrase(get_passphrase(confirm=False), salt)
    try:
        priv_raw = box.decrypt(base64.b64decode(blob["priv_enc"]))
    except Exception:
        sys.exit("wrong passphrase or corrupted key file")
    return Ed25519PrivateKey.from_private_bytes(priv_raw)


def load_enrollment(home: str) -> dict:
    rec_path = os.path.join(os.path.expanduser(home), "enrollment.json")
    if not os.path.exists(rec_path):
        sys.exit("no enrollment record at %s" % rec_path)
    return json.load(open(rec_path))


def show(args):
    rec = load_enrollment(args.home)
    print(json.dumps(rec, indent=2))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init")
    i.add_argument("--collector-id", required=True)
    i.add_argument("--token", required=True)
    i.add_argument("--home", default=DEFAULT_HOME)
    i.add_argument("--force", action="store_true")
    s = sub.add_parser("show")
    s.add_argument("--home", default=DEFAULT_HOME)
    a = ap.parse_args()
    (init if a.cmd == "init" else show)(a)
