#!/usr/bin/env bash
# Beacon Collector — dogfood profile.
# Scans THIS box's own posture, seals it, and verifies the seal locally.
# No network send: the sealed package stays on the box (org-owns-data, invariant 4).
#
# Env:
#   BEACON_BOX      label for this box (default: hostname)          -> provenance.box
#   BEACON_TARGET   filesystem root to scan (default: /host, else /)
#   BEACON_SIGN     if "1" and an enrolled key exists, sign the package (anti-forge)
#   BEACON_HOME     enrollment home for the signing key (default: ~/.beacon)
#
# Usage (on a box):
#   docker compose run --rm collector
#   # or, plain docker:
#   docker run --rm -v /:/host:ro -v "$PWD/out:/out" beacon-collector
set -euo pipefail

BOX="${BEACON_BOX:-$(hostname)}"
OUT_DIR="/out"

# Prefer a read-only host mount if present; fall back to the container root.
if [ -d /host ]; then
  TARGET="${BEACON_TARGET:-/host}"
else
  TARGET="${BEACON_TARGET:-/}"
fi

echo "== Beacon Collector (dogfood) =="
echo "   box:    ${BOX}"
echo "   target: ${TARGET}"
echo "   out:    ${OUT_DIR}"
echo "   send:   NONE (org-owns-data; sealed package stays local)"
echo

SIGN_ARGS=()
if [ "${BEACON_SIGN:-0}" = "1" ]; then
  HOME_DIR="${BEACON_HOME:-$HOME/.beacon}"
  if [ -d "${HOME_DIR}" ]; then
    SIGN_ARGS=(--sign --home "${HOME_DIR}")
    echo ">> signing enabled (enrolled key at ${HOME_DIR})"
  else
    echo ">> BEACON_SIGN=1 but no enrollment at ${HOME_DIR}; sealing UNSIGNED (hash tamper-evidence still applies)"
  fi
fi

# Collect + seal. --subject and --box both carry the box identity for a dogfood.
python /app/collector.py collect \
  --target "${TARGET}" \
  --subject "${BOX}" \
  --box "${BOX}" \
  --scope "self-posture (dogfood)" \
  --note "JawnCon dogfood: box scanning its own posture; demonstration of the open collector pipeline, not a vendor assessment." \
  --out-dir "${OUT_DIR}" \
  "${SIGN_ARGS[@]}"

# The collector writes a fixed package.json plus hashed blobs under OUT_DIR/blobs.
PKG="${OUT_DIR}/package.json"
if [ ! -f "${PKG}" ]; then
  echo "!! no package produced at ${PKG}" >&2
  exit 1
fi

echo
echo ">> sealed package: ${PKG}"
echo ">> verifying the seal on-box (proves tamper-evidence to anyone watching)..."
# verify defaults --blobs to <package-dir>/blobs, which is exactly where collect wrote them.
python /app/collector.py verify "${PKG}"

echo
echo "== done. The box has sealed its own posture. Nothing left this machine. =="
