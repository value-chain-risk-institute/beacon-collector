# Beacon Collector — dogfood image for the JawnCon deployment.
# Purpose: run the OPEN VCRI collector on a real box, scan the box's own posture,
# seal it locally. Outbound-only by design: this image opens NO listening ports.
# The public IP is the box's problem (harden the OS + Security Onion / Wazuh);
# the collector never listens, so it is not the attack surface. See README.md.

FROM python:3.12-slim

# Trivy version is a build arg so the image is reproducible. Installed from the
# release .deb with its published checksum verified, not from the upstream
# install.sh (which failed in CI on 2026-09-12 with a bare exit 1 and no message).
# Current release checked 2026-09-12: v0.74.0 (2026-08-14). Bump deliberately.
ARG TRIVY_VERSION=0.74.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates openssl \
 && cd /tmp \
 && curl -sfLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb" \
 && curl -sfLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" \
 && grep " trivy_${TRIVY_VERSION}_Linux-64bit.deb$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c - \
 && dpkg -i "trivy_${TRIVY_VERSION}_Linux-64bit.deb" \
 && rm -f trivy_* \
 && apt-get purge -y curl \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Collector source. Copy the modules explicitly so image contents are auditable.
COPY *.py /app/
# TSA trust chain, so `anchor.py verify` works offline inside the image.
COPY anchor-trust /app/anchor-trust
COPY dogfood.sh /app/dogfood.sh
RUN chmod +x /app/dogfood.sh

# Least privilege: run as a non-root user. The host filesystem is mounted read-only
# at /host (see docker-compose.yml); a non-root reader covers the vast majority of
# posture-relevant files. If a full-root scan is ever required, that is an explicit,
# documented deviation, not the default.
RUN useradd --create-home --uid 10001 beacon \
 && mkdir -p /out && chown beacon:beacon /out
USER beacon
# The container filesystem is read-only; the OpenTimestamps client keeps a small
# calendar cache, so point it at the tmpfs rather than the read-only home.
ENV XDG_CACHE_HOME=/tmp/cache

# Evidence output lands in /out (mount a volume there to keep the sealed package).
VOLUME ["/out"]

# Default: dogfood the box. Override the entrypoint for `verify`, `merge`, etc.
ENTRYPOINT ["/app/dogfood.sh"]
